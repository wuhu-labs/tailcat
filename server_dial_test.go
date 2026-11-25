// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/envknob"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/types/key"
)

func TestServerDial(t *testing.T) {
	old := os.Getenv("TS_DEBUG_NEVER_DIRECT_UDP")
	envknob.Setenv("TS_DEBUG_NEVER_DIRECT_UDP", "true")
	t.Cleanup(func() { envknob.Setenv("TS_DEBUG_NEVER_DIRECT_UDP", old) })
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	region := integration.RunDERPAndSTUN(t, mkLogger(t, "derp"), "127.0.0.1").Regions[1]
	aKey, bKey := key.NewNode(), key.NewNode()
	var aAdmitted, bAdmitted atomic.Int32
	listen := func(priv key.NodePrivate, count *atomic.Int32) (*Server, net.Listener) {
		s := &Server{
			Key: priv, Region: region, DisablePresharedKey: true, Logf: mkLogger(t, priv.Public().ShortString()),
			AllowClient: func(key.NodePublic) bool { count.Add(1); return true },
		}
		l, err := s.Listen(ctx, "tcp", ":80")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s, l
	}
	a, la := listen(aKey, &aAdmitted)
	b, lb := listen(bKey, &bAdmitted)

	type result struct {
		c   net.Conn
		err error
	}
	dial := func(s *Server, p key.NodePublic) <-chan result {
		r := make(chan result, 1)
		go func() { c, err := s.Dial(ctx, p, 80); r <- result{c, err} }()
		return r
	}
	check := func(d <-chan result, dst *Server, l net.Listener, src key.NodePublic) {
		r := <-d
		if r.err != nil {
			t.Fatal(r.err)
		}
		defer r.c.Close()
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if got, ok := dst.PeerKey(c.RemoteAddr()); !ok || got != src {
			t.Fatalf("PeerKey = %v, %v; want %v", got, ok, src)
		}
		if _, err := io.WriteString(r.c, "hello"); err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		var buf [5]byte
		if _, err := io.ReadFull(c, buf[:]); err != nil || string(buf[:]) != "hello" {
			t.Fatalf("ReadFull = %q, %v", buf, err)
		}
	}

	ab := dial(a, bKey.Public())
	ba := dial(b, aKey.Public())
	check(ab, b, lb, aKey.Public())
	check(ba, a, la, bKey.Public())
	if aAdmitted.Load() != 1 || bAdmitted.Load() != 1 {
		t.Fatalf("admission calls after cross-dial = %d, %d; want 1, 1", aAdmitted.Load(), bAdmitted.Load())
	}
	b.Close()
	b, lb = listen(bKey, &bAdmitted)
	check(dial(a, bKey.Public()), b, lb, aKey.Public())

	// A still knows B's key. This time B restarts with a policy that
	// refuses A. The new B cannot answer the first TCP SYN, and its
	// admission hook witnesses the retried meow before Dial fails.
	b.Close()
	meows := make(chan key.NodePublic, 1)
	b = &Server{
		Key: bKey, Region: region, DisablePresharedKey: true, Logf: mkLogger(t, "refusing peer"),
		AllowClient: func(peer key.NodePublic) bool {
			select {
			case meows <- peer:
			default:
			}
			return false
		},
	}
	t.Cleanup(func() { b.Close() })
	if err := b.StartContext(ctx); err != nil {
		t.Fatal(err)
	}
	dialCtx, stop := context.WithTimeout(ctx, 7*time.Second)
	defer stop()
	c, err := a.Dial(dialCtx, bKey.Public(), 80)
	if c != nil {
		c.Close()
	}
	if c != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dial after rejected refresh = %v, %v; want no stream and deadline exceeded", c, err)
	}
	select {
	case peer := <-meows:
		if peer != aKey.Public() {
			t.Fatalf("retried meow from %v; want %v", peer, aKey.Public())
		}
	default:
		t.Fatal("Dial did not retry the meow handshake with the restarted peer")
	}
}

func TestServerDialRejectsLegacyMeowed(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	region := integration.RunDERPAndSTUN(t, mkLogger(t, "derp"), "127.0.0.1").Regions[1]
	aKey, bKey := key.NewNode(), key.NewNode()
	a := &Server{Key: aKey, Region: region, DisablePresharedKey: true, Logf: mkLogger(t, "dialer")}
	t.Cleanup(func() { a.Close() })
	if err := a.StartContext(ctx); err != nil {
		t.Fatal(err)
	}

	// A peer speaking the old meow wire format sends a header-only
	// acknowledgement from its own authenticated DERP connection.
	b := derphttp.NewRegionClient(bKey, mkLogger(t, "legacy peer"), netmon.NewStatic(), func() *tailcfg.DERPRegion { return region })
	defer b.Close()
	if err := b.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	replied := make(chan error, 1)
	go func() {
		for {
			m, err := b.Recv()
			if err != nil {
				replied <- err
				return
			}
			if p, ok := m.(derp.ReceivedPacket); ok && p.Source == aKey.Public() && IsMeowPacket(p.Data) {
				if _, _, ok := ParseMeowPing(p.Data); ok {
					replied <- b.Send(p.Source, EncodeMeowed())
					return
				}
			}
		}
	}()
	c, err := a.Dial(ctx, bKey.Public(), 80)
	if c != nil {
		c.Close()
	}
	if c != nil || err == nil || ctx.Err() != nil {
		t.Fatalf("Dial with a header-only meowed reply = %v, %v; want immediate rejection", c, err)
	}
	select {
	case err := <-replied:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("legacy peer did not send its reply")
	}
}
