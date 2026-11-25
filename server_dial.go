// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"tailscale.com/types/key"
	"tailscale.com/util/mak"
)

// Dial opens a TCP stream to peer on the server's DERP region. The
// server must have started, and both peers must use the same WireGuard
// pre-shared key or both disable it. The peer's path-discovery key is
// learned during the meow handshake, not from its address.
//
// If a known peer stops responding, Dial handshakes again so a restarted
// peer can relearn this server before any stream bytes are sent.
func (s *Server) Dial(ctx context.Context, peer key.NodePublic, port uint16) (net.Conn, error) {
	s.startMu.Lock()
	lb := s.lb
	s.startMu.Unlock()
	if lb == nil {
		return nil, errors.New("tailcat: Server.Dial requires a started server")
	}
	if peer.IsZero() || peer == lb.pub || port == 0 {
		return nil, errors.New("tailcat: invalid peer or port")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopServerCancel := context.AfterFunc(lb.serverCtx, cancel)
	defer stopServerCancel()
	lb.mu.Lock()
	known := lb.clients[peer] != nil
	lb.mu.Unlock()
	dst := netip.AddrPortFrom(tcAddrForKey(peer), port)
	for attempt := range 2 {
		if !known || attempt > 0 {
			if err := lb.exchangeMeow(ctx, peer); err != nil {
				return nil, err
			}
			// A restarted peer might have lost the previous session keys.
			// Start a fresh WireGuard handshake on the next TCP SYN.
			lb.sys.Engine.Get().MarkDevicePeerForHandshake(peer)
		}
		// Leave time to refresh the handshake even when the first SYNs
		// go unanswered. Bound the second attempt too if ctx has no deadline.
		limit := 3 * time.Second
		if attempt > 0 {
			limit = 10 * time.Second
		}
		dialCtx, stop := context.WithTimeout(ctx, limit)
		conn, err := lb.ns.DialContextTCP(dialCtx, dst)
		timedOut := dialCtx.Err() == context.DeadlineExceeded
		stop()
		if err == nil {
			return conn, nil
		}
		if !timedOut || ctx.Err() != nil || attempt > 0 {
			return nil, err
		}
	}
	panic("unreachable")
}

func (b *locoBackend) exchangeMeow(ctx context.Context, peer key.NodePublic) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	replies := make(chan key.DiscoPublic, 1)
	b.mu.Lock()
	waiters := b.meowWaiters[peer]
	if waiters == nil {
		waiters = make(map[chan key.DiscoPublic]struct{})
		mak.Set(&b.meowWaiters, peer, waiters)
	}
	waiters[replies] = struct{}{}
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(waiters, replies)
		if len(waiters) == 0 {
			delete(b.meowWaiters, peer)
		}
		b.mu.Unlock()
	}()

	mc := b.sys.MagicSock.Get()
	pkt := EncodeMeowPing(b.pub, b.discoPublic())
	resend := time.NewTicker(time.Second)
	defer resend.Stop()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// DERP may drop the packet if either connection is not ready.
		mc.SendDERPPacketTo(peer, b.derpRegionID(), pkt)
		select {
		case disco := <-replies:
			if disco.IsZero() {
				return errors.New("tailcat: peer's meowed reply has no disco key")
			}
			// An admission hook must not keep Dial past ctx's deadline.
			admitted := make(chan bool, 1)
			go func() { admitted <- b.registerPeer(ctx, peer, disco) }()
			select {
			case ok := <-admitted:
				if !ok {
					return fmt.Errorf("tailcat: peer %v not admitted", peer.ShortString())
				}
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		case <-resend.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// onMeowed accepts replies only from a peer to which Dial sent a meow.
// A zero key wakes the dialer with an error for a legacy or invalid reply.
func (b *locoBackend) onMeowed(peer key.NodePublic, pkt []byte) {
	disco := meowedDiscoKey(pkt)
	b.mu.Lock()
	defer b.mu.Unlock()
	for reply := range b.meowWaiters[peer] {
		select {
		case reply <- disco:
		default:
		}
	}
}
