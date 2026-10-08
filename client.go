package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

func itoa(v int) string { return strconv.Itoa(v) }

type ClientConfig struct {
	CentralURL   string    `json:"centralURL"`
	Token        string    `json:"token"`
	CentralCA    string    `json:"centralCA"`
	EndpointID   string    `json:"endpointId"`
	AllowedCIDRs []string  `json:"allowedCIDRs"`
	AllowedPorts []int     `json:"allowedPorts"`
	Listen       string    `json:"listen"`
	FRP          FRPConfig `json:"frp"`
}
type APIClient struct {
	Base, Token string
	HTTP        *http.Client
}

func newAPI(c ClientConfig) (*APIClient, error) {
	base, e := centralURL(c.CentralURL)
	if e != nil {
		return nil, e
	}
	if !validSecret(c.Token) {
		return nil, errors.New("token must be at least 24 characters")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if c.CentralCA != "" {
		pem, e := os.ReadFile(c.CentralCA)
		if e != nil {
			return nil, e
		}
		pool, e := x509.SystemCertPool()
		if e != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid centralCA")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &APIClient{base, c.Token, &http.Client{Timeout: 5 * time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}}, nil
}
func (a *APIClient) call(ctx context.Context, method, path string, b any, out any) error {
	var data []byte
	var e error
	if b != nil {
		data, e = json.Marshal(b)
		if e != nil {
			return e
		}
	}
	q, e := http.NewRequestWithContext(ctx, method, a.Base+path, bytes.NewReader(data))
	if e != nil {
		return e
	}
	q.Header.Set("Authorization", "Bearer "+a.Token)
	q.Header.Set("Content-Type", "application/json")
	r, e := a.HTTP.Do(q)
	if e != nil {
		return errors.New("central request failed")
	}
	defer r.Body.Close()
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		var errBody map[string]string
		_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&errBody)
		return fmt.Errorf("central HTTP %d: %s", r.StatusCode, errBody["error"])
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(out)
	}
	return nil
}

type Runner struct {
	mu        sync.Mutex
	Config    ClientConfig
	Role      string
	API       *APIClient
	FRP       *FRP
	Snapshot  Snapshot
	reports   map[string]Report
	lastOK    time.Time
	lastError string
}

func NewRunner(c ClientConfig, role string) (*Runner, error) {
	api, e := newAPI(c)
	if e != nil {
		return nil, e
	}
	if role == "agent" {
		if c.EndpointID == "" {
			return nil, errors.New("endpointId required")
		}
		if e = validatePolicy(EndpointConfig{AllowedCIDRs: c.AllowedCIDRs, AllowedPorts: c.AllowedPorts}); e != nil {
			return nil, e
		}
	}
	f, e := NewFRP(c.FRP, role)
	if e != nil {
		return nil, e
	}
	return &Runner{Config: c, Role: role, API: api, FRP: f, reports: map[string]Report{}, Snapshot: Snapshot{Control: "starting", Endpoints: []EndpointView{}, Mappings: []MappingView{}}}, nil
}
func (r *Runner) Tick(ctx context.Context) error {
	var desired []Mapping
	if r.Role == "agent" {
		var d Desired
		if e := r.API.call(ctx, "POST", "/v1/agent/poll", AgentPoll{r.reports}, &d); e != nil {
			return r.failed(e)
		}
		if d.EndpointID != r.Config.EndpointID {
			return r.failed(errors.New("endpoint identity mismatch"))
		}
		for _, m := range d.Mappings {
			if m.EndpointID != r.Config.EndpointID || !m.Enabled || !targetAllowed(m, EndpointConfig{AllowedCIDRs: r.Config.AllowedCIDRs, AllowedPorts: r.Config.AllowedPorts}) {
				return r.failed(errors.New("central supplied disallowed target"))
			}
			desired = append(desired, m)
		}
	} else {
		var s Snapshot
		if e := r.API.call(ctx, "POST", "/v1/admin/poll", struct{}{}, &s); e != nil {
			return r.failed(e)
		}
		sort.Slice(s.Endpoints, func(i, j int) bool { return s.Endpoints[i].ID < s.Endpoints[j].ID })
		sort.Slice(s.Mappings, func(i, j int) bool { return s.Mappings[i].ID < s.Mappings[j].ID })
		for _, v := range s.Mappings {
			if v.Enabled && v.LeaseActive {
				desired = append(desired, v.Mapping)
			}
		}
		r.mu.Lock()
		r.Snapshot = s
		r.mu.Unlock()
	}
	r.lastOK = time.Now()
	err := r.FRP.Apply(desired)
	status := r.FRP.Status()
	if r.Role == "agent" {
		probeCtx, cancel := context.WithTimeout(ctx, time.Second)
		r.reports = collectReports(probeCtx, desired, status, err, probeTarget)
		cancel()
	} else {
		r.mu.Lock()
		r.Snapshot.Control = "online"
		if err != nil {
			r.Snapshot.Control = "frpc-error"
		}
		for i := range r.Snapshot.Mappings {
			m := &r.Snapshot.Mappings[i]
			m.Key = ""
			m.Visitor = status[m.ID]
			if !m.Enabled {
				m.Visitor = "stopped"
			}
			if err != nil && m.Enabled {
				m.Visitor = "error"
			}
		}
		r.mu.Unlock()
	}
	return err
}
func (r *Runner) failed(e error) error {
	if time.Since(r.lastOK) > 10*time.Second {
		e = errors.Join(e, r.FRP.Apply(nil))
		r.reports = map[string]Report{}
	}
	r.mu.Lock()
	r.Snapshot.Control = "offline"
	for i := range r.Snapshot.Endpoints {
		r.Snapshot.Endpoints[i].Presence = "unknown"
	}
	for i := range r.Snapshot.Mappings {
		r.Snapshot.Mappings[i].EndpointPresence = "unknown"
		r.Snapshot.Mappings[i].Provider = "unknown"
		r.Snapshot.Mappings[i].Target = "unknown"
		r.Snapshot.Mappings[i].Visitor = "unknown"
		r.Snapshot.Mappings[i].Key = ""
	}
	r.mu.Unlock()
	return e
}
func (r *Runner) Run(ctx context.Context) {
	defer r.FRP.Close()
	timer := time.NewTicker(2 * time.Second)
	defer timer.Stop()
	for {
		e := r.Tick(ctx)
		if e != nil {
			if e.Error() != r.lastError {
				fmt.Fprintln(os.Stderr, e)
				r.lastError = e.Error()
			}
		} else {
			r.lastError = ""
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}

// A single budget covers the WHOLE batch, including waiting for a worker slot.
// Health checks must never delay polling or revocation proportional to map count.
func collectReports(ctx context.Context, desired []Mapping, status map[string]string, frpErr error, probe func(context.Context, string, int) string) map[string]Report {
	reports := map[string]Report{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, m := range desired {
		wg.Add(1)
		go func(m Mapping) {
			defer wg.Done()
			target := "unknown"
			select {
			case sem <- struct{}{}:
				if ctx.Err() == nil {
					target = probe(ctx, m.TargetIP, m.TargetPort)
				}
				<-sem
			case <-ctx.Done():
			}
			p := status[m.ID]
			if p == "" {
				p = "unknown"
			}
			if frpErr != nil {
				p = "error"
			}
			mu.Lock()
			reports[m.ID] = Report{p, target}
			mu.Unlock()
		}(m)
	}
	wg.Wait()
	return reports
}
