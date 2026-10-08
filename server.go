package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type ServerConfig struct {
	Listen       string           `json:"listen"`
	TLSCert      string           `json:"tlsCert"`
	TLSKey       string           `json:"tlsKey"`
	AdminToken   string           `json:"adminToken"`
	Endpoints    []EndpointConfig `json:"endpoints"`
	LeaseSeconds int              `json:"leaseSeconds"`
	MaxMappings  int              `json:"maxMappings"`
}
type endpointState struct {
	Config  EndpointConfig
	Seen    time.Time
	Reports map[string]Report
}
type Registry struct {
	mu        sync.Mutex
	config    ServerConfig
	endpoints map[string]*endpointState
	mappings  map[string]Mapping
	adminSeen time.Time
	lease     time.Duration
}

func NewRegistry(c ServerConfig) (*Registry, error) {
	if !validSecret(c.AdminToken) {
		return nil, errors.New("adminToken must be at least 24 characters")
	}
	if c.LeaseSeconds == 0 {
		c.LeaseSeconds = 15
	}
	if c.LeaseSeconds < 5 || c.LeaseSeconds > 120 {
		return nil, errors.New("leaseSeconds must be 5..120")
	}
	if c.MaxMappings == 0 {
		c.MaxMappings = 64
	}
	if c.MaxMappings < 1 || c.MaxMappings > 1024 {
		return nil, errors.New("maxMappings must be 1..1024")
	}
	r := &Registry{config: c, endpoints: map[string]*endpointState{}, mappings: map[string]Mapping{}, lease: time.Duration(c.LeaseSeconds) * time.Second}
	tokens := map[string]bool{c.AdminToken: true}
	for _, e := range c.Endpoints {
		if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(e.ID) || r.endpoints[e.ID] != nil {
			return nil, errors.New("invalid or duplicate endpoint ID")
		}
		if !validSecret(e.Token) || tokens[e.Token] {
			return nil, errors.New("endpoint tokens must be unique, at least 24 characters")
		}
		if err := validatePolicy(e); err != nil {
			return nil, err
		}
		tokens[e.Token] = true
		r.endpoints[e.ID] = &endpointState{Config: e, Reports: map[string]Report{}}
	}
	return r, nil
}
func (r *Registry) live(now time.Time) bool { return now.Sub(r.adminSeen) < r.lease }
func (r *Registry) view(m Mapping, now time.Time, withKey bool) MappingView {
	e := r.endpoints[m.EndpointID]
	presence := "offline"
	if now.Sub(e.Seen) < r.lease {
		presence = "online"
	}
	v := MappingView{Mapping: m, EndpointPresence: presence, Provider: "inactive", Target: "unknown", LeaseActive: r.live(now)}
	if !withKey {
		v.Key = ""
	}
	if m.Enabled && v.LeaseActive && presence == "online" {
		v.Provider = "pending"
		if x, ok := e.Reports[m.ID]; ok {
			v.Provider = x.Proxy
			v.Target = x.Target
		}
	}
	return v
}
func (r *Registry) ServeHTTP(w http.ResponseWriter, q *http.Request) {
	// Read the bounded body before the registry lock: slow peers cannot block heartbeats.
	if q.Method == "POST" || q.Method == "PATCH" {
		body, err := io.ReadAll(http.MaxBytesReader(w, q.Body, 65536))
		q.Body.Close()
		if err != nil {
			failure(w, 400, "request body exceeds limit or could not be read")
			return
		}
		q.Body = io.NopCloser(bytes.NewReader(body))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	path := q.URL.Path
	if path == "/v1/agent/poll" && q.Method == "POST" {
		var endpoint *endpointState
		for _, e := range r.endpoints {
			if auth(q, e.Config.Token) {
				endpoint = e
				break
			}
		}
		if endpoint == nil {
			failure(w, 401, "unauthorized")
			return
		}
		var b AgentPoll
		if decode(q, &b) != nil {
			failure(w, 400, "invalid reports")
			return
		}
		endpoint.Seen = now
		endpoint.Reports = map[string]Report{}
		for id, x := range b.Reports {
			m, ok := r.mappings[id]
			if !ok || m.EndpointID != endpoint.Config.ID {
				continue
			}
			switch x.Proxy {
			case "running", "starting", "error", "reconnecting", "unknown":
			default:
				x.Proxy = "unknown"
			}
			switch x.Target {
			case "reachable", "unreachable", "unknown":
			default:
				x.Target = "unknown"
			}
			endpoint.Reports[id] = x
		}
		d := Desired{EndpointID: endpoint.Config.ID, Mappings: []Mapping{}}
		if r.live(now) {
			for _, m := range r.mappings {
				if m.EndpointID == endpoint.Config.ID && m.Enabled {
					d.Mappings = append(d.Mappings, m)
				}
			}
		}
		respond(w, 200, d)
		return
	}
	if !auth(q, r.config.AdminToken) {
		failure(w, 401, "unauthorized")
		return
	}
	if path == "/v1/admin/poll" && q.Method == "POST" {
		r.adminSeen = now
		s := Snapshot{Endpoints: []EndpointView{}, Mappings: []MappingView{}, Control: "online"}
		for _, e := range r.endpoints {
			presence := "offline"
			if now.Sub(e.Seen) < r.lease {
				presence = "online"
			}
			s.Endpoints = append(s.Endpoints, EndpointView{e.Config.ID, e.Config.Name, presence})
		}
		for _, m := range r.mappings {
			s.Mappings = append(s.Mappings, r.view(m, now, true))
		}
		respond(w, 200, s)
		return
	}
	if path == "/v1/mappings" && q.Method == "POST" {
		var b struct {
			EndpointID string `json:"endpointId"`
			TargetIP   string `json:"targetIP"`
			TargetPort int    `json:"targetPort"`
			LocalPort  int    `json:"localPort"`
		}
		if decode(q, &b) != nil {
			failure(w, 400, "invalid mapping")
			return
		}
		e := r.endpoints[b.EndpointID]
		m := Mapping{ID: randomHex(12), EndpointID: b.EndpointID, TargetIP: b.TargetIP, TargetPort: b.TargetPort, LocalPort: b.LocalPort, Enabled: true, Key: randomHex(32)}
		if e == nil || !validPort(m.LocalPort) || !targetAllowed(m, e.Config) {
			failure(w, 400, "invalid endpoint, port, or target outside allowlist")
			return
		}
		if len(r.mappings) >= r.config.MaxMappings {
			failure(w, 409, "mapping limit reached")
			return
		}
		for _, x := range r.mappings {
			if x.LocalPort == m.LocalPort {
				failure(w, 409, "local port already assigned")
				return
			}
		}
		r.mappings[m.ID] = m
		respond(w, 201, r.view(m, now, false))
		return
	}
	if strings.HasPrefix(path, "/v1/mappings/") {
		id := strings.TrimPrefix(path, "/v1/mappings/")
		m, ok := r.mappings[id]
		if !ok {
			failure(w, 404, "mapping not found")
			return
		}
		if q.Method == "DELETE" {
			delete(r.mappings, id)
			respond(w, 200, map[string]bool{"ok": true})
			return
		}
		if q.Method == "PATCH" {
			var b struct {
				Enabled *bool `json:"enabled"`
			}
			if decode(q, &b) != nil || b.Enabled == nil {
				failure(w, 400, "enabled boolean required")
				return
			}
			m.Enabled = *b.Enabled
			r.mappings[id] = m
			respond(w, 200, r.view(m, now, false))
			return
		}
	}
	failure(w, 404, "not found")
}
