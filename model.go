package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type Mapping struct {
	ID         string `json:"id"`
	EndpointID string `json:"endpointId"`
	TargetIP   string `json:"targetIP"`
	TargetPort int    `json:"targetPort"`
	LocalPort  int    `json:"localPort"`
	Enabled    bool   `json:"enabled"`
	Key        string `json:"key,omitempty"`
}
type Report struct {
	Proxy  string `json:"proxy"`
	Target string `json:"target"`
}
type EndpointConfig struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Token        string   `json:"token"`
	AllowedCIDRs []string `json:"allowedCIDRs"`
	AllowedPorts []int    `json:"allowedPorts,omitempty"`
}
type EndpointView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Presence string `json:"presence"`
}
type MappingView struct {
	Mapping
	EndpointPresence string `json:"endpointPresence"`
	Provider         string `json:"provider"`
	Target           string `json:"target"`
	Visitor          string `json:"visitor,omitempty"`
	LeaseActive      bool   `json:"leaseActive"`
}
type Snapshot struct {
	Endpoints []EndpointView `json:"endpoints"`
	Mappings  []MappingView  `json:"mappings"`
	Control   string         `json:"control"`
}
type AgentPoll struct {
	Reports map[string]Report `json:"reports"`
}
type Desired struct {
	EndpointID string    `json:"endpointId"`
	Mappings   []Mapping `json:"mappings"`
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func validSecret(s string) bool { return len(s) >= 24 && !strings.Contains(s, "REPLACE") }
func auth(r *http.Request, token string) bool {
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) == 1
}
func validPort(p int) bool { return p > 0 && p < 65536 }
func targetAllowed(m Mapping, c EndpointConfig) bool {
	a, e := netip.ParseAddr(m.TargetIP)
	if e != nil || !validPort(m.TargetPort) {
		return false
	}
	ok := false
	for _, s := range c.AllowedCIDRs {
		p, e := netip.ParsePrefix(s)
		if e == nil && p.Contains(a) {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	if len(c.AllowedPorts) == 0 {
		return true
	}
	for _, p := range c.AllowedPorts {
		if p == m.TargetPort {
			return true
		}
	}
	return false
}
func validatePolicy(c EndpointConfig) error {
	if len(c.AllowedCIDRs) == 0 {
		return errors.New("allowedCIDRs must explicitly allow target networks")
	}
	for _, s := range c.AllowedCIDRs {
		if _, e := netip.ParsePrefix(s); e != nil {
			return e
		}
	}
	for _, p := range c.AllowedPorts {
		if !validPort(p) {
			return errors.New("invalid allowed port")
		}
	}
	return nil
}
func decode(r *http.Request, v any) error {
	defer r.Body.Close()
	d := json.NewDecoder(io.LimitReader(r.Body, 65537))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func failure(w http.ResponseWriter, status int, s string) {
	respond(w, status, map[string]string{"error": s})
}
func centralURL(s string) (string, error) {
	u, e := url.Parse(s)
	if e != nil {
		return "", e
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return "", errors.New("centralURL must be an origin")
	}
	ip := net.ParseIP(u.Hostname())
	local := ip != nil && ip.IsLoopback()
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return "", errors.New("central API requires HTTPS except literal loopback")
	}
	if u.Host == "" {
		return "", errors.New("central host required")
	}
	return strings.TrimSuffix(s, "/"), nil
}
func probeTarget(ctx context.Context, ip string, p int) string {
	d := net.Dialer{Timeout: 700 * time.Millisecond}
	c, e := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, itoa(p)))
	if e != nil {
		if ctx.Err() != nil {
			return "unknown"
		}
		return "unreachable"
	}
	c.Close()
	return "reachable"
}
