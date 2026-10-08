package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func frpTestMapping(id string, port int) Mapping {
	return Mapping{ID: id, EndpointID: "endpoint-a", TargetIP: "127.0.0.1", TargetPort: 3389,
		LocalPort: port, Key: strings.Repeat("a", 32), Enabled: true}
}

func TestFRPConfigSecureAndStable(t *testing.T) {
	f := &FRP{c: FRPConfig{ServerAddr: "relay.example", ServerPort: 7000, Token: strings.Repeat("b", 32),
		TrustedCA: "/private/ca.pem", ServerName: "relay.example"}, role: "admin", apiPort: 45123, password: "ephemeral"}
	a, b := frpTestMapping("a", 43001), frpTestMapping("b", 43002)
	one, err := f.config([]Mapping{a, b})
	if err != nil {
		t.Fatal(err)
	}
	two, err := f.config([]Mapping{b, a})
	if err != nil || !bytes.Equal(one, two) {
		t.Fatal("mapping reorder changed generated configuration")
	}
	var parsed map[string]any
	if err := json.Unmarshal(one, &parsed); err != nil {
		t.Fatal(err)
	}
	if _, exists := parsed["user"]; exists {
		t.Fatal("user prefix must not be set")
	}
	if parsed["loginFailExit"] != false {
		t.Fatal("frpc must retry login")
	}
	web := parsed["webServer"].(map[string]any)
	if web["addr"] != "127.0.0.1" || web["password"] != "ephemeral" {
		t.Fatal("unsafe web API")
	}
	tls := parsed["transport"].(map[string]any)["tls"].(map[string]any)
	if tls["enable"] != true || tls["trustedCaFile"] != "/private/ca.pem" {
		t.Fatal("missing verified TLS")
	}
	visitors := parsed["visitors"].([]any)
	for _, v := range visitors {
		vc := v.(map[string]any)
		if vc["bindAddr"] != "127.0.0.1" || vc["name"] != vc["serverName"] || vc["type"] != "stcp" {
			t.Fatal("unsafe visitor")
		}
	}
	a.Enabled = false
	disabled, _ := f.config([]Mapping{a, b})
	if bytes.Contains(disabled, []byte(`"rt-a"`)) {
		t.Fatal("disabled mapping emitted")
	}
	f.role = "agent"
	agent, err := f.config([]Mapping{b})
	if err != nil || !bytes.Contains(agent, []byte(`"localIP": "127.0.0.1"`)) {
		t.Fatal("provider target missing")
	}
}

func TestFRPRejectsUnsafeInputs(t *testing.T) {
	base := FRPConfig{Binary: "not-used", ServerAddr: "127.0.0.1", ServerPort: 7000, Token: strings.Repeat("a", 32), InsecureLocalTest: true}
	for name, change := range map[string]func(*FRPConfig){
		"remote insecure":   func(c *FRPConfig) { c.ServerAddr = "relay.example" },
		"hostname insecure": func(c *FRPConfig) { c.ServerAddr = "localhost" },
		"missing CA":        func(c *FRPConfig) { c.InsecureLocalTest = false },
		"short token":       func(c *FRPConfig) { c.Token = "short" },
		"placeholder token": func(c *FRPConfig) { c.Token = "REPLACE_WITH_LONG_RANDOM_TOKEN" },
		"template token":    func(c *FRPConfig) { c.Token += "{{ .Envs.HOME }}" },
		"invalid port":      func(c *FRPConfig) { c.ServerPort = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			change(&c)
			if _, err := NewFRP(c, "agent"); err == nil {
				t.Fatal("accepted unsafe configuration")
			}
		})
	}
	f := &FRP{role: "admin", apiPort: 45000}
	a := frpTestMapping("a", 43000)
	for name, mappings := range map[string][]Mapping{
		"duplicate ID":       {a, a},
		"duplicate port":     {a, frpTestMapping("b", 43000)},
		"API port collision": {frpTestMapping("b", 45000)},
		"invalid ID":         {frpTestMapping("../b", 43001)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.config(mappings); err == nil {
				t.Fatal("accepted invalid mappings")
			}
		})
	}
}

func TestFRPStatusDoesNotClaimTargetReachability(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "remotetool" || p != "password" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		io.WriteString(w, `{"stcp":[{"name":"rt-a","status":"running","err":""},{"name":"rt-b","status":"start error","err":"sensitive detail"}]}`)
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	p, _ := strconv.Atoi(port)
	f := &FRP{role: "agent", password: "password", apiPort: p, client: srv.Client(),
		proc:     &frpProcess{done: make(chan struct{}), started: time.Now()},
		mappings: []Mapping{frpTestMapping("a", 43001), frpTestMapping("b", 43002)}}
	if status := f.Status(); status["a"] != "running" || status["b"] != "error" {
		t.Fatalf("unexpected status: %v", status)
	}
	f.role = "admin"
	if status := f.Status(); status["a"] != "configured-unverified" {
		t.Fatalf("visitor claims unverified runtime health: %v", status)
	}
	close(f.proc.done)
	if status := f.Status(); status["a"] != "reconnecting" {
		t.Fatalf("dead process retained status: %v", status)
	}
}

func TestFRPAtomicPrivateConfig(t *testing.T) {
	f := &FRP{dir: t.TempDir()}
	f.path = filepath.Join(f.dir, "frpc.json")
	for _, content := range []string{"one", "two"} {
		if err := f.writeConfig([]byte(content)); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(f.path)
		if err != nil || string(data) != content {
			t.Fatal("configuration replacement failed")
		}
		st, err := os.Stat(f.path)
		if err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0600) {
			t.Fatal("configuration is not mode 0600")
		}
	}
}

func TestFRPRevocationRequiresRestart(t *testing.T) {
	a := frpTestMapping("a", 43001)
	b := frpTestMapping("b", 43002)
	if frpNeedsRestart([]Mapping{a}, []Mapping{b, a}) {
		t.Fatal("addition should preserve the existing process and streams")
	}
	if !frpNeedsRestart([]Mapping{a, b}, []Mapping{a}) {
		t.Fatal("deletion must close established streams")
	}
	for name, change := range map[string]func(*Mapping){
		"disable":      func(m *Mapping) { m.Enabled = false },
		"target IP":    func(m *Mapping) { m.TargetIP = "127.0.0.2" },
		"target port":  func(m *Mapping) { m.TargetPort++ },
		"visitor port": func(m *Mapping) { m.LocalPort++ },
		"secret":       func(m *Mapping) { m.Key = strings.Repeat("b", 32) },
		"endpoint":     func(m *Mapping) { m.EndpointID = "endpoint-b" },
	} {
		t.Run(name, func(t *testing.T) {
			next := a
			change(&next)
			if !frpNeedsRestart([]Mapping{a}, []Mapping{next}) {
				t.Fatal("authorization change must close established streams")
			}
		})
	}
}

// Opt in with FRPC_BIN and FRPS_BIN pointing at official 0.71.0 binaries.
// This exercises real verified TLS, STCP bytes, live reload, crash recovery,
// and lease revocation. All listeners are confined to loopback.
func TestFRPRealReloadAndRecovery(t *testing.T) {
	frpc, frps := os.Getenv("FRPC_BIN"), os.Getenv("FRPS_BIN")
	if dir := os.Getenv("FRP_TEST_DIR"); dir != "" {
		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		if frpc == "" {
			frpc = filepath.Join(dir, "frpc"+ext)
		}
		if frps == "" {
			frps = filepath.Join(dir, "frps"+ext)
		}
	}
	if frpc == "" || frps == "" {
		t.Skip("set FRPC_BIN and FRPS_BIN for real FRP integration")
	}
	dir := t.TempDir()
	cert, key := frpTestCertificate(t, dir)
	relayPort := frpTestFreePort(t)
	token := strings.Repeat("r", 32)
	serverConfig, _ := json.Marshal(map[string]any{
		"bindAddr": "127.0.0.1", "bindPort": relayPort,
		"auth":      map[string]any{"method": "token", "token": token},
		"transport": map[string]any{"tls": map[string]any{"force": true, "certFile": cert, "keyFile": key}},
		"log":       map[string]any{"level": "error", "to": "console"},
	})
	serverPath := filepath.Join(dir, "frps.json")
	if err := os.WriteFile(serverPath, serverConfig, 0600); err != nil {
		t.Fatal(err)
	}
	server := exec.Command(frps, "-c", serverPath)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	cfg := FRPConfig{Binary: frpc, ServerAddr: "127.0.0.1", ServerPort: relayPort, Token: token, TrustedCA: cert, ServerName: "localhost", RuntimeDir: dir}
	provider, err := NewFRP(cfg, "agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	visitor, err := NewFRP(cfg, "admin")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = visitor.Close() })
	a := frpTestMapping("a", frpTestFreePort(t))
	a.TargetPort = listener.Addr().(*net.TCPAddr).Port
	b := frpTestMapping("b", frpTestFreePort(t))
	b.TargetPort = a.TargetPort
	if err := provider.Apply([]Mapping{a}); err != nil {
		t.Fatal(err)
	}
	if err := visitor.Apply([]Mapping{a}); err != nil {
		t.Fatal(err)
	}
	frpTestEventually(t, 15*time.Second, func() bool { return frpTestEcho(a.LocalPort) == nil })
	if status := provider.Status(); status["a"] != "running" {
		t.Fatalf("provider status: %v", status)
	}
	if status := visitor.Status(); status["a"] != "configured-unverified" {
		t.Fatalf("visitor status: %v", status)
	}
	persistent, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(a.LocalPort)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer persistent.Close()
	frpTestRoundTrip(t, persistent)
	providerPID, visitorPID := provider.proc.cmd.Process.Pid, visitor.proc.cmd.Process.Pid
	before, _ := os.Stat(provider.path)
	if err := provider.Apply([]Mapping{a}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(provider.path)
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("unchanged configuration was rewritten")
	}
	if err := provider.Apply([]Mapping{b, a}); err != nil {
		t.Fatal(err)
	}
	if err := visitor.Apply([]Mapping{a, b}); err != nil {
		t.Fatal(err)
	}
	if provider.proc.cmd.Process.Pid != providerPID || visitor.proc.cmd.Process.Pid != visitorPID {
		t.Fatal("reload restarted frpc")
	}
	frpTestEventually(t, 8*time.Second, func() bool { return frpTestEcho(b.LocalPort) == nil })
	frpTestRoundTrip(t, persistent)
	removedStream, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(b.LocalPort)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer removedStream.Close()
	frpTestRoundTrip(t, removedStream)
	b.Enabled = false
	if err := provider.Apply([]Mapping{a, b}); err != nil {
		t.Fatal(err)
	}
	if err := visitor.Apply([]Mapping{a, b}); err != nil {
		t.Fatal(err)
	}
	frpTestEventually(t, 3*time.Second, func() bool { return frpTestEcho(b.LocalPort) != nil })
	_ = removedStream.SetDeadline(time.Now().Add(time.Second))
	_, writeErr := removedStream.Write([]byte("revoked"))
	_, readErr := removedStream.Read(make([]byte, 7))
	if writeErr == nil && readErr == nil {
		t.Fatal("disabled mapping retained an established stream")
	}
	if provider.proc.cmd.Process.Pid == providerPID || visitor.proc.cmd.Process.Pid == visitorPID {
		t.Fatal("revocation must restart frpc to close established streams")
	}
	frpTestEventually(t, 8*time.Second, func() bool { return frpTestEcho(a.LocalPort) == nil })
	_ = provider.proc.cmd.Process.Kill()
	<-provider.proc.done
	if err := provider.Apply([]Mapping{a}); err == nil {
		t.Fatal("crash restart skipped backoff")
	}
	frpTestEventually(t, 8*time.Second, func() bool { return provider.Apply([]Mapping{a}) == nil && frpTestEcho(a.LocalPort) == nil })
	if provider.proc.cmd.Process.Pid == providerPID {
		t.Fatal("crashed process was not replaced")
	}
	if err := visitor.Apply(nil); err != nil {
		t.Fatal(err)
	}
	if visitor.proc != nil {
		t.Fatal("lease loss left visitor process running")
	}
	if err := frpTestEcho(a.LocalPort); err == nil {
		t.Fatal("lease loss left mapping reachable")
	}
	if err := provider.Apply(nil); err != nil {
		t.Fatal(err)
	}
	if err := visitor.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(visitor.dir); !os.IsNotExist(err) {
		t.Fatal("runtime state not removed")
	}
}

func frpTestFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func frpTestEventually(t *testing.T, timeout time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("timed out waiting for real FRP state")
}

func frpTestEcho(port int) error {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 250*time.Millisecond)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := c.Write([]byte("frp-roundtrip")); err != nil {
		return err
	}
	b := make([]byte, len("frp-roundtrip"))
	_, err = io.ReadFull(c, b)
	if err == nil && string(b) != "frp-roundtrip" {
		return io.ErrUnexpectedEOF
	}
	return err
}

func frpTestRoundTrip(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("kept-open")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len("kept-open"))
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "kept-open" {
		t.Fatalf("existing stream interrupted: %v", err)
	}
}

func frpTestCertificate(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
