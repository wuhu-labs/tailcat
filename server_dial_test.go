// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"context"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/tstest/integration"
	"tailscale.com/types/key"
)

func TestServerDial(t *testing.T) {
	old := os.Getenv("TS_DEBUG_NEVER_DIRECT_UDP")
	envknob.Setenv("TS_DEBUG_NEVER_DIRECT_UDP", "true")
	t.Cleanup(func() { envknob.Setenv("TS_DEBUG_NEVER_DIRECT_UDP", old) })
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
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
}
