package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// These tests intentionally use stock FRP executables, not a fake supervisor or
// transport. Run with FRP_TEST_DIR pointing at the extracted v0.71.0 release.
// Every token, configuration, listener, and process exists only for this test.
func TestFRPIntegrationLifecycle(t *testing.T) {
	h := newFRPIntegration(t)
	targetA := integrationEcho(t, "alpha", 0)
	targetB := integrationEcho(t, "beta", 0)
	m1 := h.add(targetA.port())
	h.await("first mapping carries target payload", 20*time.Second, func() error {
		h.tick()
		return integrationExchange(m1.LocalPort, "alpha", "initial\n")
	})
	h.await("online endpoint and registered provider", 10*time.Second, func() error {
		h.tick()
		return h.checkView(m1.ID, "online", "running", "reachable")
	})

	// A long-lived socket proves reloads preserve existing streams, rather than
	// merely hiding disruption behind reconnecting clients.
	persistent := integrationDial(t, m1.LocalPort)
	defer persistent.Close()
	if err := integrationOnConn(persistent, "alpha", "before-add\n"); err != nil {
		t.Fatal(err)
	}
	m2 := h.add(targetB.port())
	h.await("second mapping carries its own target payload", 15*time.Second, func() error {
		h.tick()
		return integrationExchange(m2.LocalPort, "beta", "second-mapping\n")
	})
	if err := integrationOnConn(persistent, "alpha", "after-add\n"); err != nil {
		t.Fatalf("adding another mapping disrupted an existing stream: %v", err)
	}
	t.Log("two mappings forward distinct target payloads; add preserved an open stream")

	var wg sync.WaitGroup
	errs := make(chan error, 24)
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			port, label := m1.LocalPort, "alpha"
			if i%2 != 0 {
				port, label = m2.LocalPort, "beta"
			}
			payload := fmt.Sprintf("connection-%d-%s\n", i, strings.Repeat("payload-", 8192))
			if err := integrationExchange(port, label, payload); err != nil {
				errs <- fmt.Errorf("connection %d: %w", i, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		t.FailNow()
	}
	t.Log("24 concurrent TCP sessions passed exact 64 KiB payload checks across both mappings")

	// Revoking one mapping must terminate its existing streams too. Stock FRP
	// reload alone drains those streams, so destructive changes restart the
	// shared client. Unrelated mappings remain configured and reconnect.
	stoppedStream := integrationDial(t, m2.LocalPort)
	defer stoppedStream.Close()
	if err := integrationOnConn(stoppedStream, "beta", "before-disable\n"); err != nil {
		t.Fatal(err)
	}
	h.enable(m2.ID, false)
	h.await("stopping one of two mappings revokes its listener and provider", 10*time.Second, func() error {
		h.tick()
		if err := integrationPortClosed(m2.LocalPort); err != nil {
			return err
		}
		return integrationProviderAbsent(h.agent.FRP, m2.ID)
	})
	if err := integrationStreamClosed(stoppedStream); err != nil {
		t.Fatalf("stopped mapping retained its existing stream: %v", err)
	}
	h.await("unrelated mapping recovers after stop", 15*time.Second, func() error {
		h.tick()
		return integrationExchange(m1.LocalPort, "alpha", "after-other-stop\n")
	})
	h.enable(m2.ID, true)
	h.await("stopped mapping restarts", 15*time.Second, func() error {
		h.tick()
		return integrationExchange(m2.LocalPort, "beta", "after-reenable\n")
	})

	removedStream := integrationDial(t, m2.LocalPort)
	defer removedStream.Close()
	if err := integrationOnConn(removedStream, "beta", "before-delete\n"); err != nil {
		t.Fatal(err)
	}
	h.remove(m2.ID)
	h.await("deleted visitor closes its local port", 10*time.Second, func() error {
		h.tick()
		return integrationPortClosed(m2.LocalPort)
	})
	h.await("deleted provider disappears from real frpc status", 10*time.Second, func() error {
		return integrationProviderAbsent(h.agent.FRP, m2.ID)
	})
	if err := integrationStreamClosed(removedStream); err != nil {
		t.Fatalf("deleted mapping retained its existing stream: %v", err)
	}
	h.await("unrelated mapping recovers after delete", 15*time.Second, func() error {
		h.tick()
		return integrationExchange(m1.LocalPort, "alpha", "after-other-delete\n")
	})
	if _, ok := h.view(m2.ID); ok {
		t.Fatal("deleted mapping remains in admin snapshot")
	}
	t.Log("stop and delete revoked existing streams; unrelated mapping recovered after shared-client restart")

	finalStream := integrationDial(t, m1.LocalPort)
	defer finalStream.Close()
	if err := integrationOnConn(finalStream, "alpha", "before-final-stop\n"); err != nil {
		t.Fatal(err)
	}
	h.enable(m1.ID, false)
	h.await("stop closes the last local listener", 10*time.Second, func() error {
		h.tick()
		return integrationPortClosed(m1.LocalPort)
	})
	if err := integrationStreamClosed(finalStream); err != nil {
		t.Fatalf("stopped final mapping retained its existing stream: %v", err)
	}
	if err := integrationProviderAbsent(h.agent.FRP, m1.ID); err != nil {
		t.Fatal(err)
	}
	if v, ok := h.view(m1.ID); !ok || v.Enabled || v.Visitor != "stopped" {
		t.Fatalf("stopped mapping should remain visible as stopped: %+v", v)
	}
	h.enable(m1.ID, true)
	h.await("start restores forwarding", 15*time.Second, func() error {
		h.tick()
		return integrationExchange(m1.LocalPort, "alpha", "after-start\n")
	})
	t.Log("stop/start closed and restored the local listener and end-to-end payload")

	// The control-plane presence heartbeat is deliberately kept separate from
	// the service probe. An online agent can have an unavailable target.
	unavailablePort := integrationFreePort(t)
	m3 := h.add(unavailablePort)
	h.await("unavailable service does not mark endpoint offline", 15*time.Second, func() error {
		h.tick()
		return h.checkView(m3.ID, "online", "running", "unreachable")
	})
	if err := integrationExchange(m3.LocalPort, "gamma", "must-not-work\n"); err == nil {
		t.Fatal("unavailable target unexpectedly returned a payload")
	}
	targetC := integrationEcho(t, "gamma", unavailablePort)
	h.await("target comes online without agent restart", 15*time.Second, func() error {
		h.tick()
		if err := h.checkView(m3.ID, "online", "running", "reachable"); err != nil {
			return err
		}
		return integrationExchange(m3.LocalPort, "gamma", "target-recovered\n")
	})
	targetC.close()
	h.await("target outage is reported independently again", 10*time.Second, func() error {
		h.tick()
		return h.checkView(m3.ID, "online", "running", "unreachable")
	})
	h.remove(m3.ID)
	h.tick()
	t.Log("target unavailable/recovery is distinct from endpoint presence and provider registration")

	if err := h.agent.FRP.Close(); err != nil {
		t.Fatal(err)
	}
	h.await("stopped endpoint eventually goes offline", 8*time.Second, func() error {
		if err := h.admin.Tick(context.Background()); err != nil {
			return err
		}
		v, _ := h.view(m1.ID)
		if v.EndpointPresence != "offline" {
			return fmt.Errorf("presence still %q", v.EndpointPresence)
		}
		return nil
	})
	h.agent = h.newRunner("agent")
	h.await("endpoint agent restart restores the same mapping", 20*time.Second, func() error {
		h.tick()
		return integrationExchange(m1.LocalPort, "alpha", "agent-restarted\n")
	})
	t.Log("endpoint went offline after lease expiry, then a fresh agent restored the existing mapping")

	h.frps.stop(t)
	h.await("frps outage interrupts forwarding", 8*time.Second, func() error {
		h.tick()
		if err := integrationExchange(m1.LocalPort, "alpha", "during-relay-outage\n"); err == nil {
			return fmt.Errorf("forwarding still works after relay stopped")
		}
		return nil
	})
	h.frps.start(t)
	h.await("frps restart recovers without recreating runners or mapping", 35*time.Second, func() error {
		h.tick()
		return integrationExchange(m1.LocalPort, "alpha", "relay-restarted\n")
	})
	t.Log("stock frps restart recovered end-to-end without recreating either Runner")

	h.remove(m1.ID)
	h.await("deleting final mapping closes local port and provider", 10*time.Second, func() error {
		h.tick()
		if err := integrationPortClosed(m1.LocalPort); err != nil {
			return err
		}
		return integrationProviderAbsent(h.agent.FRP, m1.ID)
	})
	if len(h.admin.Snapshot.Mappings) != 0 {
		t.Fatal("final delete left mappings in the admin snapshot")
	}
}

func TestFRPIntegrationControlLossFailsClosed(t *testing.T) {
	h := newFRPIntegration(t)
	target := integrationEcho(t, "control", 0)
	m := h.add(target.port())
	h.await("initial forwarding", 20*time.Second, func() error {
		h.tick()
		return integrationExchange(m.LocalPort, "control", "before-loss\n")
	})
	stream := integrationDial(t, m.LocalPort)
	defer stream.Close()
	if err := integrationOnConn(stream, "control", "before-control-loss\n"); err != nil {
		t.Fatal(err)
	}
	h.central.Close()
	// Wait through the production ten-second grace period, using genuine failed
	// HTTP requests and clock time instead of modifying Runner.lastOK.
	h.await("central API loss revokes local listeners and providers", 15*time.Second, func() error {
		adminErr := h.admin.Tick(context.Background())
		agentErr := h.agent.Tick(context.Background())
		if adminErr == nil || agentErr == nil {
			return fmt.Errorf("central requests unexpectedly succeeded")
		}
		if err := integrationPortClosed(m.LocalPort); err != nil {
			return err
		}
		return integrationProviderAbsent(h.agent.FRP, m.ID)
	})
	if err := integrationStreamClosed(stream); err != nil {
		t.Fatalf("control loss retained an existing stream: %v", err)
	}
	if h.admin.Snapshot.Control != "offline" {
		t.Fatalf("control status = %q, want offline", h.admin.Snapshot.Control)
	}
	v, _ := h.view(m.ID)
	if v.Target != "unknown" || v.Provider != "unknown" || v.Key != "" {
		t.Fatalf("offline snapshot claims stale health or exposes secret: %+v", v)
	}
	t.Log("real central HTTP outage closed listeners and providers after production grace period")
}

func TestFRPIntegrationAdminLeaseExpires(t *testing.T) {
	h := newFRPIntegration(t)
	target := integrationEcho(t, "lease", 0)
	m := h.add(target.port())
	h.await("initial forwarding", 20*time.Second, func() error {
		h.tick()
		return integrationExchange(m.LocalPort, "lease", "lease-start\n")
	})
	// An admin app exits, its visitor exits with it, and the live agent must
	// independently withdraw its provider after the registry's five-second lease.
	if err := h.admin.FRP.Close(); err != nil {
		t.Fatal(err)
	}
	h.await("admin lease expiry withdraws the endpoint provider", 9*time.Second, func() error {
		if err := h.agent.Tick(context.Background()); err != nil {
			return err
		}
		return integrationProviderAbsent(h.agent.FRP, m.ID)
	})
	if err := integrationPortClosed(m.LocalPort); err != nil {
		t.Fatal(err)
	}
	h.admin = h.newRunner("admin")
	h.await("new admin restores the saved mapping and renews lease", 20*time.Second, func() error {
		h.tick()
		return integrationExchange(m.LocalPort, "lease", "lease-renewed\n")
	})
	t.Log("admin exit revoked provider on lease expiry; fresh admin restored the mapping")
}

type frpIntegration struct {
	t          *testing.T
	central    *httptest.Server
	frps       *integrationFRPServer
	agent      *Runner
	admin      *Runner
	frpConfig  FRPConfig
	agentToken string
	adminToken string
}

func newFRPIntegration(t *testing.T) *frpIntegration {
	t.Helper()
	binDir := os.Getenv("FRP_TEST_DIR")
	if binDir == "" {
		t.Skip("real FRP integration: set FRP_TEST_DIR to an extracted stock v0.71.0 release")
	}
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	for _, binary := range []string{"frpc", "frps"} {
		if err := checkFRPVersion(context.Background(), filepath.Join(binDir, binary+ext)); err != nil {
			t.Fatalf("FRP_TEST_DIR must provide stock %s %s: %v", binary, requiredFRPVersion, err)
		}
	}
	h := &frpIntegration{t: t, agentToken: randomHex(32), adminToken: randomHex(32)}
	registry, err := NewRegistry(ServerConfig{
		AdminToken: h.adminToken, LeaseSeconds: 5,
		Endpoints: []EndpointConfig{{ID: "integration-endpoint", Name: "Integration endpoint", Token: h.agentToken, AllowedCIDRs: []string{"127.0.0.0/8"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.central = httptest.NewServer(registry)
	t.Cleanup(h.central.Close)
	h.frps = newIntegrationFRPServer(t, filepath.Join(binDir, "frps"+ext))
	h.frpConfig = FRPConfig{Binary: filepath.Join(binDir, "frpc"+ext), ServerAddr: "127.0.0.1", ServerPort: h.frps.port, Token: h.frps.token, RuntimeDir: t.TempDir(), InsecureLocalTest: true}
	h.admin = h.newRunner("admin")
	h.agent = h.newRunner("agent")
	t.Cleanup(func() {
		if h.agent != nil {
			_ = h.agent.FRP.Close()
		}
		if h.admin != nil {
			_ = h.admin.FRP.Close()
		}
	})
	return h
}

func (h *frpIntegration) newRunner(role string) *Runner {
	h.t.Helper()
	c := ClientConfig{CentralURL: h.central.URL, Token: h.adminToken, FRP: h.frpConfig}
	if role == "agent" {
		c.Token, c.EndpointID, c.AllowedCIDRs = h.agentToken, "integration-endpoint", []string{"127.0.0.0/8"}
	}
	r, err := NewRunner(c, role)
	if err != nil {
		h.t.Fatal(err)
	}
	return r
}

func (h *frpIntegration) add(targetPort int) Mapping {
	h.t.Helper()
	var v MappingView
	body := map[string]any{"endpointId": "integration-endpoint", "targetIP": "127.0.0.1", "targetPort": targetPort, "localPort": integrationFreePort(h.t)}
	if err := h.admin.API.call(context.Background(), http.MethodPost, "/v1/mappings", body, &v); err != nil {
		h.t.Fatal(err)
	}
	if v.ID == "" || v.Key != "" {
		h.t.Fatal("mapping creation must return an ID without its secret key")
	}
	return v.Mapping
}
func (h *frpIntegration) enable(id string, enabled bool) {
	h.t.Helper()
	if err := h.admin.API.call(context.Background(), http.MethodPatch, "/v1/mappings/"+id, map[string]bool{"enabled": enabled}, nil); err != nil {
		h.t.Fatal(err)
	}
}
func (h *frpIntegration) remove(id string) {
	h.t.Helper()
	if err := h.admin.API.call(context.Background(), http.MethodDelete, "/v1/mappings/"+id, nil, nil); err != nil {
		h.t.Fatal(err)
	}
}
func (h *frpIntegration) tick() {
	// Polls are serial, like each production Runner's own loop. Errors during
	// process startup/reconnect are expected; end-to-end assertions decide when
	// recovery has actually happened instead of trusting a process-start result.
	_ = h.admin.Tick(context.Background())
	_ = h.agent.Tick(context.Background())
	_ = h.admin.Tick(context.Background())
}
func (h *frpIntegration) view(id string) (MappingView, bool) {
	for _, v := range h.admin.Snapshot.Mappings {
		if v.ID == id {
			return v, true
		}
	}
	return MappingView{}, false
}
func (h *frpIntegration) checkView(id, presence, provider, target string) error {
	v, ok := h.view(id)
	if !ok || v.EndpointPresence != presence || v.Provider != provider || v.Target != target {
		return fmt.Errorf("mapping %s: presence=%q provider=%q target=%q; want %q/%q/%q", id, v.EndpointPresence, v.Provider, v.Target, presence, provider, target)
	}
	if v.Key != "" {
		return fmt.Errorf("admin display snapshot exposes mapping key")
	}
	return nil
}
func (h *frpIntegration) await(description string, timeout time.Duration, check func() error) {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	var err error
	for {
		if err = check(); err == nil {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("%s did not complete in %s: %v", description, timeout, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

type integrationFRPServer struct {
	binary, path, token string
	port                int
	cmd                 *exec.Cmd
	log                 *os.File
}

func newIntegrationFRPServer(t *testing.T, binary string) *integrationFRPServer {
	t.Helper()
	s := &integrationFRPServer{binary: binary, path: filepath.Join(t.TempDir(), "frps.json"), token: randomHex(32), port: integrationFreePort(t)}
	config := map[string]any{
		"bindAddr": "127.0.0.1", "bindPort": s.port,
		"auth":      map[string]any{"method": "token", "token": s.token},
		"transport": map[string]any{"tls": map[string]any{"force": true}},
		"log":       map[string]any{"to": "console", "level": "error", "disablePrintColor": true},
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(s.path, data, 0600); err != nil {
		t.Fatal(err)
	}
	s.start(t)
	t.Cleanup(func() { s.stop(t) })
	return s
}
func (s *integrationFRPServer) start(t *testing.T) {
	t.Helper()
	var err error
	s.log, err = os.OpenFile(s.path+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	s.cmd = exec.Command(s.binary, "-c", s.path)
	s.cmd.Env = frpEnvironment()
	s.cmd.Stdout, s.cmd.Stderr = s.log, s.log
	if err = s.cmd.Start(); err != nil {
		_ = s.log.Close()
		t.Fatal(err)
	}
	deadline := time.Now().Add(frpStartupTimeout)
	for {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(s.port)), 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			s.stop(t)
			// Do not print process output or config; failures must not leak tokens.
			t.Fatal("stock frps did not open its loopback control listener")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
func (s *integrationFRPServer) stop(t *testing.T) {
	t.Helper()
	if s.cmd != nil {
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
		s.cmd = nil
	}
	if s.log != nil {
		_ = s.log.Close()
		s.log = nil
	}
}

type integrationEchoServer struct {
	listener net.Listener
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	closed   bool
}

func integrationEcho(t *testing.T, label string, port int) *integrationEchoServer {
	t.Helper()
	ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	s := &integrationEchoServer{listener: ln, conns: make(map[net.Conn]struct{})}
	t.Cleanup(s.close)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				_ = c.Close()
				return
			}
			s.conns[c] = struct{}{}
			s.mu.Unlock()
			go func() {
				defer func() {
					_ = c.Close()
					s.mu.Lock()
					delete(s.conns, c)
					s.mu.Unlock()
				}()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if _, err = io.WriteString(c, label+":"+line); err != nil {
						return
					}
				}
			}()
		}
	}()
	return s
}
func (s *integrationEchoServer) port() int { return s.listener.Addr().(*net.TCPAddr).Port }
func (s *integrationEchoServer) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	_ = s.listener.Close()
	for c := range s.conns {
		_ = c.Close()
	}
}
func integrationFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}
func integrationDial(t *testing.T, port int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func integrationExchange(port int, label, payload string) error {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), 2*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	return integrationOnConn(c, label, payload)
}
func integrationOnConn(c net.Conn, label, payload string) error {
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c, payload); err != nil {
		return err
	}
	want := []byte(label + ":" + payload)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("target payload mismatch (got %d bytes, expected %d)", len(got), len(want))
	}
	return nil
}
func integrationPortClosed(port int) error {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), 200*time.Millisecond)
	if err == nil {
		_ = c.Close()
		return fmt.Errorf("local port %d still accepts connections", port)
	}
	// Successful rebind verifies the listener was really released.
	ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		return fmt.Errorf("local port %d cannot be rebound: %w", port, err)
	}
	return ln.Close()
}
func integrationProviderAbsent(f *FRP, id string) error {
	q, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+itoa(f.apiPort)+"/api/status", nil)
	q.SetBasicAuth("remotetool", f.password)
	resp, err := f.client.Do(q)
	if err != nil {
		f.mu.Lock()
		alive := f.aliveLocked()
		f.mu.Unlock()
		if !alive {
			return nil // No provider can remain in a terminated real frpc process.
		}
		return fmt.Errorf("cannot inspect live provider process: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("frpc status HTTP %d", resp.StatusCode)
	}
	var all map[string][]struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&all); err != nil {
		return err
	}
	for _, s := range all["stcp"] {
		if s.Name == "rt-"+id {
			return fmt.Errorf("provider %s remains in real frpc status", id)
		}
	}
	return nil
}

// A read timeout means the connection still exists, not that it was revoked.
// Assert a real EOF/reset, with no pending response data from previous requests.
func integrationStreamClosed(c net.Conn) error {
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var one [1]byte
	n, err := c.Read(one[:])
	if n != 0 || err == nil {
		return fmt.Errorf("stream still returned data")
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		return fmt.Errorf("stream remained open until deadline")
	}
	return nil
}
