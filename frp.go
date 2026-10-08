package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const requiredFRPVersion = "0.71.0"

// Cold process startup can take several seconds on Windows. This budget is
// only for initialization, before any mapping or control-plane lease exists.
const frpStartupTimeout = 15 * time.Second

type FRPConfig struct {
	Binary            string `json:"binary"`
	ServerAddr        string `json:"serverAddr"`
	Token             string `json:"token"`
	TrustedCA         string `json:"trustedCA"`
	ServerName        string `json:"serverName"`
	RuntimeDir        string `json:"runtimeDir"`
	ServerPort        int    `json:"serverPort"`
	InsecureLocalTest bool   `json:"insecureLocalTest"`
}

// FRP owns one stock frpc process. All process/configuration operations are
// serialized. Apply is called by the control-plane lease loop, including when
// the desired set is empty; it never silently retains a rejected configuration.
type FRP struct {
	mu              sync.Mutex
	c               FRPConfig
	role            string
	dir             string
	path            string
	apiPort         int
	password        string
	client          *http.Client
	proc            *frpProcess
	mappings        []Mapping
	runningMappings []Mapping
	applied         []byte
	retryAt         time.Time
	backoff         time.Duration
	closed          bool
}

type frpProcess struct {
	cmd     *exec.Cmd
	done    chan struct{}
	started time.Time
}

var frpMappingID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func NewFRP(c FRPConfig, role string) (*FRP, error) {
	if role != "agent" && role != "admin" {
		return nil, errors.New("FRP role must be agent or admin")
	}
	if c.ServerAddr == "" || strings.ContainsAny(c.ServerAddr, "/\\ \t\r\n\x00{}") ||
		(strings.Contains(c.ServerAddr, ":") && net.ParseIP(c.ServerAddr) == nil) {
		return nil, errors.New("FRP serverAddr must be a host or literal IP without a port")
	}
	if c.ServerPort < 1 || c.ServerPort > 65535 {
		return nil, errors.New("FRP serverPort must be between 1 and 65535")
	}
	if len(c.Token) < 24 || len(c.Token) > 4096 || strings.Contains(c.Token, "{{") || strings.Contains(c.Token, "REPLACE") {
		return nil, errors.New("FRP token must have at least 24 characters and cannot contain template syntax")
	}
	if strings.ContainsAny(c.ServerName, "\x00\r\n{}") {
		return nil, errors.New("invalid FRP TLS server name")
	}
	if c.ServerName == "" {
		c.ServerName = c.ServerAddr
	}
	ip := net.ParseIP(c.ServerAddr)
	if c.InsecureLocalTest && (ip == nil || !ip.IsLoopback()) {
		return nil, errors.New("insecureLocalTest requires a literal loopback FRP server address")
	}
	var ca []byte
	if c.TrustedCA != "" {
		var err error
		ca, err = os.ReadFile(c.TrustedCA)
		if err != nil {
			return nil, errors.New("cannot read FRP trusted CA")
		}
		if !x509.NewCertPool().AppendCertsFromPEM(ca) {
			return nil, errors.New("FRP trusted CA contains no valid PEM certificates")
		}
	} else if !c.InsecureLocalTest {
		return nil, errors.New("FRP trustedCA is required for verified TLS")
	}
	if c.Binary == "" {
		return nil, errors.New("FRP binary is required")
	}
	binary, err := exec.LookPath(c.Binary)
	if err != nil {
		return nil, errors.New("FRP binary was not found")
	}
	c.Binary, err = filepath.Abs(binary)
	if err != nil {
		return nil, err
	}
	if err := checkFRPVersion(context.Background(), c.Binary); err != nil {
		return nil, err
	}
	root := c.RuntimeDir
	if root == "" {
		root = os.TempDir()
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, fmt.Errorf("create FRP runtime parent: %w", err)
	}
	dir, err := os.MkdirTemp(root, "remotetool-frpc-"+role+"-")
	if err != nil {
		return nil, fmt.Errorf("create private FRP runtime: %w", err)
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	f := &FRP{c: c, role: role, dir: dir, path: filepath.Join(dir, "frpc.json")}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(dir)
		}
	}()
	if len(ca) != 0 {
		// Snapshot validated trust into our private directory, so each restart uses
		// the same explicitly supplied trust roots.
		f.c.TrustedCA = filepath.Join(dir, "trusted-ca.pem")
		if err := os.WriteFile(f.c.TrustedCA, ca, 0600); err != nil {
			return nil, fmt.Errorf("write FRP trust roots: %w", err)
		}
	}
	password := make([]byte, 32)
	if _, err := rand.Read(password); err != nil {
		return nil, err
	}
	f.password = hex.EncodeToString(password)
	// frpc treats webServer.port=0 as disabled. Reserve an OS-assigned loopback
	// port, then release it for frpc. A bind race is safe: frpc fails to start.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("reserve FRP API port: %w", err)
	}
	f.apiPort = ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	f.client = &http.Client{
		Timeout:   800 * time.Millisecond,
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("FRP API redirects are not permitted")
		},
	}
	ok = true
	return f, nil
}

// checkFRPVersion keeps startup failure distinct from a successfully reported
// unsupported version. Never include subprocess output in diagnostics.
func checkFRPVersion(parent context.Context, binary string) error {
	ctx, cancel := context.WithTimeout(parent, frpStartupTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--version")
	// Bound waiting for inherited output pipes as well as the process itself.
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("FRP version check timed out (startup budget %s): %w", frpStartupTimeout, ctx.Err())
			}
			return fmt.Errorf("FRP version check canceled: %w", ctx.Err())
		}
		return fmt.Errorf("FRP version check could not execute successfully: %w", err)
	}
	if strings.TrimSpace(string(out)) != requiredFRPVersion {
		return fmt.Errorf("FRP binary must report exactly version %s", requiredFRPVersion)
	}
	return nil
}

func (f *FRP) config(mappings []Mapping) ([]byte, error) {
	tls := map[string]any{"enable": true, "serverName": f.c.ServerName}
	if f.c.TrustedCA != "" {
		tls["trustedCaFile"] = f.c.TrustedCA
	}
	proxies := make([]any, 0)
	visitors := make([]any, 0)
	ordered := append([]Mapping(nil), mappings...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	ids, ports := map[string]bool{}, map[int]bool{}
	endpoint := ""
	for _, m := range ordered {
		if !frpMappingID.MatchString(m.ID) || ids[m.ID] {
			return nil, errors.New("invalid or duplicate FRP mapping ID")
		}
		ids[m.ID] = true
		if !m.Enabled {
			continue
		}
		if len(m.Key) < 24 || len(m.Key) > 4096 || strings.Contains(m.Key, "{{") {
			return nil, errors.New("FRP mapping secret must have at least 24 characters and no template syntax")
		}
		name := "rt-" + m.ID
		if f.role == "agent" {
			if net.ParseIP(m.TargetIP) == nil || m.TargetPort < 1 || m.TargetPort > 65535 {
				return nil, errors.New("invalid FRP target IP or port")
			}
			if endpoint != "" && endpoint != m.EndpointID {
				return nil, errors.New("one FRP agent cannot provide multiple endpoints")
			}
			endpoint = m.EndpointID
			proxies = append(proxies, map[string]any{
				"name": name, "type": "stcp", "secretKey": m.Key,
				"localIP": m.TargetIP, "localPort": m.TargetPort,
				"transport": map[string]any{"useEncryption": true},
			})
		} else {
			if m.LocalPort < 1 || m.LocalPort > 65535 || ports[m.LocalPort] || m.LocalPort == f.apiPort {
				return nil, errors.New("invalid, duplicate, or reserved FRP visitor port")
			}
			ports[m.LocalPort] = true
			visitors = append(visitors, map[string]any{
				"name": name, "type": "stcp", "serverName": name, "secretKey": m.Key,
				"bindAddr": "127.0.0.1", "bindPort": m.LocalPort,
				"transport": map[string]any{"useEncryption": true},
			})
		}
	}
	data, err := json.MarshalIndent(map[string]any{
		"serverAddr": f.c.ServerAddr, "serverPort": f.c.ServerPort,
		"loginFailExit": false,
		"auth":          map[string]any{"method": "token", "token": f.c.Token},
		"transport":     map[string]any{"tls": tls},
		"log":           map[string]any{"to": "console", "level": "error", "disablePrintColor": true},
		"webServer":     map[string]any{"addr": "127.0.0.1", "port": f.apiPort, "user": "remotetool", "password": f.password},
		"proxies":       proxies, "visitors": visitors,
	}, "", "  ")
	if err == nil && bytes.Contains(data, []byte("{{")) {
		return nil, errors.New("generated FRP configuration cannot contain template syntax")
	}
	return data, err
}

func (f *FRP) Apply(mappings []Mapping) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return errors.New("FRP supervisor is closed")
	}
	data, err := f.config(mappings)
	if err != nil {
		stopErr := f.stopLocked()
		f.mappings = nil
		return errors.Join(err, stopErr)
	}
	f.mappings = append([]Mapping(nil), mappings...)
	active := false
	for _, m := range mappings {
		active = active || m.Enabled
	}
	if !active {
		// Lease loss must close listeners even if the admin API is unresponsive.
		stopErr := f.stopLocked()
		writeErr := f.writeConfig(data)
		return errors.Join(stopErr, writeErr)
	}
	alive := f.aliveLocked()
	if alive && frpNeedsRestart(f.runningMappings, mappings) {
		// Stock frpc reload removes listeners/proxies, but existing forwarded TCP
		// streams can survive removal. Restart on revocation or authorization
		// changes so disabled mappings cannot keep established sessions alive.
		// This necessarily interrupts other mappings in this same frpc instance.
		if err := f.stopLocked(); err != nil {
			return err
		}
		alive = false
	}
	if alive && bytes.Equal(data, f.applied) {
		return nil
	}
	if err := f.writeConfig(data); err != nil {
		return errors.Join(err, f.stopLocked())
	}
	if !alive {
		if time.Now().Before(f.retryAt) {
			return errors.New("FRP restart is backing off")
		}
		return f.startLocked(data)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, f.c.Binary, "reload", "-c", f.path, "--api-timeout", "2s")
	cmd.Env = frpEnvironment()
	// Do not relay frpc output: errors can include secret-bearing config data.
	if err := cmd.Run(); err != nil {
		stopErr := f.stopLocked()
		f.failedLocked()
		return errors.Join(errors.New("FRP reload failed; stopping client to fail closed"), stopErr)
	}
	f.applied = append(f.applied[:0], data...)
	f.runningMappings = append([]Mapping(nil), mappings...)
	return nil
}

func frpNeedsRestart(old, next []Mapping) bool {
	wanted := make(map[string]Mapping, len(next))
	for _, m := range next {
		if m.Enabled {
			wanted[m.ID] = m
		}
	}
	for _, m := range old {
		if !m.Enabled {
			continue
		}
		n, ok := wanted[m.ID]
		if !ok || n.EndpointID != m.EndpointID || n.TargetIP != m.TargetIP ||
			n.TargetPort != m.TargetPort || n.LocalPort != m.LocalPort || n.Key != m.Key {
			return true
		}
	}
	return false
}

func (f *FRP) writeConfig(data []byte) error {
	file, err := os.CreateTemp(f.dir, ".frpc-*.json")
	if err != nil {
		return fmt.Errorf("create private FRP config: %w", err)
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp, f.path)
	}
	if err != nil {
		return fmt.Errorf("replace private FRP config: %w", err)
	}
	return nil
}

func frpEnvironment() []string {
	env := make([]string, 0, len(os.Environ()))
	for _, item := range os.Environ() {
		key := strings.ToLower(strings.SplitN(item, "=", 2)[0])
		// Stock frpc reads http_proxy for its control transport. Never inherit an
		// implicit relay for the control connection or local admin credentials.
		if key != "http_proxy" && key != "https_proxy" && key != "all_proxy" {
			env = append(env, item)
		}
	}
	return env
}

func (f *FRP) startLocked(data []byte) error {
	cmd := exec.Command(f.c.Binary, "-c", f.path)
	cmd.Env = frpEnvironment()
	setFRPProcessAttributes(cmd)
	if err := cmd.Start(); err != nil {
		f.failedLocked()
		return errors.New("cannot start FRP client")
	}
	p := &frpProcess{cmd: cmd, done: make(chan struct{}), started: time.Now()}
	f.proc = p
	go func() { _ = cmd.Wait(); close(p.done) }()
	f.applied = append([]byte(nil), data...)
	f.runningMappings = append([]Mapping(nil), f.mappings...)
	return nil
}

func (f *FRP) failedLocked() {
	if f.backoff == 0 {
		f.backoff = time.Second
	} else {
		f.backoff *= 2
		if f.backoff > 30*time.Second {
			f.backoff = 30 * time.Second
		}
	}
	f.retryAt = time.Now().Add(f.backoff)
}

func (f *FRP) aliveLocked() bool {
	if f.proc == nil {
		return false
	}
	select {
	case <-f.proc.done:
		f.proc = nil
		f.applied = nil
		f.runningMappings = nil
		f.failedLocked()
		return false
	default:
		if time.Since(f.proc.started) > 30*time.Second {
			f.backoff = 0
		}
		return true
	}
}

// Status deliberately separates process/configuration state from target health.
// FRP v0.71.0 /api/status is a type-keyed object of provider arrays, with NO
// visitor runtime status. Its "running" only means the proxy registered at frps.
// Sources: client/http/controller.go and client/http/model/types.go at v0.71.0.
func (f *FRP) Status() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make(map[string]string, len(f.mappings))
	alive := f.aliveLocked()
	for _, m := range f.mappings {
		switch {
		case !m.Enabled:
			result[m.ID] = "disabled"
		case !alive || f.closed:
			result[m.ID] = "reconnecting"
		default:
			result[m.ID] = "starting"
		}
	}
	if !alive || f.closed {
		return result
	}
	url := "http://127.0.0.1:" + strconv.Itoa(f.apiPort) + "/api/status"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return result
	}
	req.SetBasicAuth("remotetool", f.password)
	resp, err := f.client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return result
	}
	var status map[string][]struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Err    string `json:"err"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&status); err != nil {
		return result
	}
	if f.role == "admin" {
		for _, m := range f.mappings {
			if m.Enabled {
				result[m.ID] = "configured-unverified"
			}
		}
		return result
	}
	for _, s := range status["stcp"] {
		id := strings.TrimPrefix(s.Name, "rt-")
		if result[id] != "starting" || s.Name != "rt-"+id {
			continue
		}
		switch {
		case s.Err != "":
			result[id] = "error"
		case s.Status == "running":
			result[id] = "running"
		case s.Status == "start error":
			result[id] = "error"
		case s.Status == "closed":
			result[id] = "reconnecting"
		case s.Status == "check failed":
			result[id] = "error"
		}
	}
	return result
}

func (f *FRP) stopLocked() error {
	if f.proc == nil {
		f.applied = nil
		f.runningMappings = nil
		return nil
	}
	p := f.proc
	select {
	case <-p.done:
	default:
		if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
			_ = p.cmd.Process.Kill()
		}
		select {
		case <-p.done:
		case <-time.After(1500 * time.Millisecond):
			_ = p.cmd.Process.Kill()
			select {
			case <-p.done:
			case <-time.After(1500 * time.Millisecond):
				return errors.New("FRP client did not terminate")
			}
		}
	}
	f.proc = nil
	f.applied = nil
	f.runningMappings = nil
	return nil
}

func (f *FRP) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	if err := f.stopLocked(); err != nil {
		return err
	}
	f.client.CloseIdleConnections()
	return os.RemoveAll(f.dir)
}
