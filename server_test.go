package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	testAdminToken = "admin-test-token-0123456789abcdef0123456789"
	testAlphaToken = "alpha-test-token-0123456789abcdef0123456789"
	testBravoToken = "bravo-test-token-0123456789abcdef0123456789"
)

func testServerConfig() ServerConfig {
	return ServerConfig{
		AdminToken:   testAdminToken,
		LeaseSeconds: 5,
		Endpoints: []EndpointConfig{
			{ID: "alpha", Name: "Alpha", Token: testAlphaToken, AllowedCIDRs: []string{"10.10.0.0/24", "2001:db8:1::/64"}, AllowedPorts: []int{22, 443}},
			{ID: "bravo", Name: "Bravo", Token: testBravoToken, AllowedCIDRs: []string{"192.168.20.0/24"}, AllowedPorts: []int{3389}},
		},
	}
}

func testRegistry(t *testing.T) *Registry {
	t.Helper()
	r, err := NewRegistry(testServerConfig())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func testRequest(t *testing.T, r http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	return testRawRequest(t, r, method, path, token, string(data))
}

func testRawRequest(t *testing.T, r http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	q := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		q.Header.Set("Authorization", "Bearer "+token)
	}
	q.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, q)
	return w
}

func testStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, want, w.Body.String())
	}
}

func testJSON[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode response: %v; body: %s", err, w.Body.String())
	}
	return v
}

func testCreate(t *testing.T, r *Registry, endpoint, ip string, targetPort, localPort int) MappingView {
	t.Helper()
	w := testRequest(t, r, http.MethodPost, "/v1/mappings", testAdminToken, map[string]any{
		"endpointId": endpoint, "targetIP": ip, "targetPort": targetPort, "localPort": localPort,
	})
	testStatus(t, w, http.StatusCreated)
	m := testJSON[MappingView](t, w)
	if m.ID == "" {
		t.Fatal("created mapping has no ID")
	}
	return m
}

func testAdminPoll(t *testing.T, r *Registry) Snapshot {
	t.Helper()
	w := testRequest(t, r, http.MethodPost, "/v1/admin/poll", testAdminToken, nil)
	testStatus(t, w, http.StatusOK)
	return testJSON[Snapshot](t, w)
}

func testAgentPoll(t *testing.T, r *Registry, token string, reports map[string]Report) Desired {
	t.Helper()
	w := testRequest(t, r, http.MethodPost, "/v1/agent/poll", token, AgentPoll{Reports: reports})
	testStatus(t, w, http.StatusOK)
	return testJSON[Desired](t, w)
}

func testSnapshotMapping(t *testing.T, s Snapshot, id string) MappingView {
	t.Helper()
	for _, m := range s.Mappings {
		if m.ID == id {
			return m
		}
	}
	t.Fatalf("mapping %s missing from snapshot", id)
	return MappingView{}
}

func TestRegistryAuthentication(t *testing.T) {
	r := testRegistry(t)
	m := testCreate(t, r, "alpha", "10.10.0.10", 22, 10022)
	for _, token := range []string{"", "wrong-token", testAlphaToken, testBravoToken} {
		for _, route := range []struct{ method, path, body string }{
			{http.MethodPost, "/v1/admin/poll", "{}"},
			{http.MethodPost, "/v1/mappings", `{"endpointId":"alpha","targetIP":"10.10.0.10","targetPort":22,"localPort":11022}`},
			{http.MethodPatch, "/v1/mappings/" + m.ID, `{"enabled":false}`},
			{http.MethodDelete, "/v1/mappings/" + m.ID, ""},
		} {
			t.Run(fmt.Sprintf("%s/%s/%s", token, route.method, route.path), func(t *testing.T) {
				w := testRawRequest(t, r, route.method, route.path, token, route.body)
				testStatus(t, w, http.StatusUnauthorized)
			})
		}
	}
	for _, token := range []string{"", "wrong-token", testAdminToken} {
		w := testRequest(t, r, http.MethodPost, "/v1/agent/poll", token, AgentPoll{})
		testStatus(t, w, http.StatusUnauthorized)
	}
	if !r.adminSeen.IsZero() {
		t.Fatal("unauthorized request renewed admin lease")
	}
	if len(r.mappings) != 1 || !r.mappings[m.ID].Enabled {
		t.Fatal("unauthorized request modified registry")
	}
	for _, e := range r.endpoints {
		if !e.Seen.IsZero() {
			t.Fatal("unauthorized request updated endpoint presence")
		}
	}
}

func TestRegistryEndpointIsolation(t *testing.T) {
	r := testRegistry(t)
	a := testCreate(t, r, "alpha", "10.10.0.10", 22, 10022)
	b := testCreate(t, r, "bravo", "192.168.20.10", 3389, 13389)
	testAdminPoll(t, r)
	ad := testAgentPoll(t, r, testAlphaToken, map[string]Report{
		a.ID:          {Proxy: "running", Target: "reachable"},
		b.ID:          {Proxy: "error", Target: "unreachable"},
		"nonexistent": {Proxy: "running", Target: "reachable"},
	})
	if ad.EndpointID != "alpha" || len(ad.Mappings) != 1 || ad.Mappings[0].ID != a.ID {
		t.Fatalf("alpha received foreign mappings: %+v", ad)
	}
	if ad.Mappings[0].Key == "" {
		t.Fatal("agent did not receive its STCP key")
	}
	if len(r.endpoints["alpha"].Reports) != 1 {
		t.Fatal("foreign or unknown report was retained")
	}
	bd := testAgentPoll(t, r, testBravoToken, nil)
	if bd.EndpointID != "bravo" || len(bd.Mappings) != 1 || bd.Mappings[0].ID != b.ID {
		t.Fatalf("bravo received foreign mappings: %+v", bd)
	}
	if ad.Mappings[0].Key == bd.Mappings[0].Key {
		t.Fatal("endpoints share a mapping key")
	}
	bv := testSnapshotMapping(t, testAdminPoll(t, r), b.ID)
	if bv.Provider != "pending" || bv.Target != "unknown" {
		t.Fatalf("alpha spoofed bravo status: %+v", bv)
	}
}

func TestRegistryMappingLifecycle(t *testing.T) {
	r := testRegistry(t)
	testAdminPoll(t, r)
	m := testCreate(t, r, "alpha", "10.10.0.10", 22, 10022)
	if !m.Enabled || m.Key != "" {
		t.Fatalf("unexpected create response: %+v", m)
	}
	d := testAgentPoll(t, r, testAlphaToken, nil)
	if len(d.Mappings) != 1 || d.Mappings[0].ID != m.ID {
		t.Fatalf("new mapping not desired: %+v", d)
	}
	key := d.Mappings[0].Key
	for _, enabled := range []bool{false, true} {
		w := testRequest(t, r, http.MethodPatch, "/v1/mappings/"+m.ID, testAdminToken, map[string]bool{"enabled": enabled})
		testStatus(t, w, http.StatusOK)
		v := testJSON[MappingView](t, w)
		if v.Enabled != enabled || v.Key != "" {
			t.Fatalf("unexpected patch response: %+v", v)
		}
		d = testAgentPoll(t, r, testAlphaToken, nil)
		if enabled {
			if len(d.Mappings) != 1 || d.Mappings[0].Key != key {
				t.Fatalf("restart changed mapping identity: %+v", d)
			}
		} else if len(d.Mappings) != 0 {
			t.Fatalf("stopped mapping remains desired: %+v", d)
		}
	}
	w := testRequest(t, r, http.MethodDelete, "/v1/mappings/"+m.ID, testAdminToken, nil)
	testStatus(t, w, http.StatusOK)
	if len(testAgentPoll(t, r, testAlphaToken, nil).Mappings) != 0 {
		t.Fatal("deleted mapping remains desired")
	}
	if len(testAdminPoll(t, r).Mappings) != 0 {
		t.Fatal("deleted mapping remains in snapshot")
	}
	w = testRequest(t, r, http.MethodDelete, "/v1/mappings/"+m.ID, testAdminToken, nil)
	testStatus(t, w, http.StatusNotFound)
	// Deletion releases the visitor port.
	testCreate(t, r, "alpha", "10.10.0.11", 22, 10022)
}

func TestRegistryDuplicateLocalPort(t *testing.T) {
	r := testRegistry(t)
	m := testCreate(t, r, "alpha", "10.10.0.10", 22, 10022)
	for _, stop := range []bool{false, true} {
		if stop {
			w := testRequest(t, r, http.MethodPatch, "/v1/mappings/"+m.ID, testAdminToken, map[string]bool{"enabled": false})
			testStatus(t, w, http.StatusOK)
		}
		w := testRequest(t, r, http.MethodPost, "/v1/mappings", testAdminToken, map[string]any{
			"endpointId": "bravo", "targetIP": "192.168.20.10", "targetPort": 3389, "localPort": 10022,
		})
		testStatus(t, w, http.StatusConflict)
	}
	if len(r.mappings) != 1 {
		t.Fatal("duplicate mapping was stored")
	}
}

func TestRegistryAdminLeaseExpiration(t *testing.T) {
	r := testRegistry(t)
	m := testCreate(t, r, "alpha", "10.10.0.10", 22, 10022)
	if len(testAgentPoll(t, r, testAlphaToken, nil).Mappings) != 0 {
		t.Fatal("mapping active before administrator lease exists")
	}
	testAdminPoll(t, r)
	if len(testAgentPoll(t, r, testAlphaToken, nil).Mappings) != 1 {
		t.Fatal("mapping not active during administrator lease")
	}
	r.mu.Lock()
	r.adminSeen = time.Now().Add(-r.lease - time.Second)
	r.mu.Unlock()
	if len(testAgentPoll(t, r, testAlphaToken, nil).Mappings) != 0 {
		t.Fatal("endpoint poll revived expired administrator lease")
	}
	v := r.view(r.mappings[m.ID], time.Now(), false)
	if v.LeaseActive || v.Provider != "inactive" {
		t.Fatalf("expired lease still active: %+v", v)
	}
	// CRUD activity alone must not revive the lease.
	w := testRequest(t, r, http.MethodPatch, "/v1/mappings/"+m.ID, testAdminToken, map[string]bool{"enabled": true})
	testStatus(t, w, http.StatusOK)
	if len(testAgentPoll(t, r, testAlphaToken, nil).Mappings) != 0 {
		t.Fatal("mapping mutation revived expired administrator lease")
	}
	testAdminPoll(t, r)
	if len(testAgentPoll(t, r, testAlphaToken, nil).Mappings) != 1 {
		t.Fatal("administrator renewal did not restore desired mapping")
	}
}

func TestRegistryReportFreshnessAndSanitization(t *testing.T) {
	r := testRegistry(t)
	m := testCreate(t, r, "alpha", "10.10.0.10", 22, 10022)
	testAdminPoll(t, r)
	testAgentPoll(t, r, testAlphaToken, map[string]Report{m.ID: {Proxy: "running", Target: "reachable"}})
	v := testSnapshotMapping(t, testAdminPoll(t, r), m.ID)
	if v.EndpointPresence != "online" || v.Provider != "running" || v.Target != "reachable" {
		t.Fatalf("fresh report missing: %+v", v)
	}
	r.mu.Lock()
	r.endpoints["alpha"].Seen = time.Now().Add(-r.lease - time.Second)
	r.mu.Unlock()
	v = testSnapshotMapping(t, testAdminPoll(t, r), m.ID)
	if v.EndpointPresence != "offline" || v.Provider != "inactive" || v.Target != "unknown" {
		t.Fatalf("stale report still represented as live: %+v", v)
	}
	// A fresh empty report replaces the old report rather than refreshing it.
	testAgentPoll(t, r, testAlphaToken, map[string]Report{})
	v = testSnapshotMapping(t, testAdminPoll(t, r), m.ID)
	if v.EndpointPresence != "online" || v.Provider != "pending" || v.Target != "unknown" {
		t.Fatalf("empty poll retained old report: %+v", v)
	}
	testAgentPoll(t, r, testAlphaToken, map[string]Report{m.ID: {Proxy: "<script>bad</script>", Target: "arbitrary text"}})
	v = testSnapshotMapping(t, testAdminPoll(t, r), m.ID)
	if v.Provider != "unknown" || v.Target != "unknown" {
		t.Fatalf("unrecognized report accepted: %+v", v)
	}
}

func TestRegistryMutationResponsesDoNotLeakSecrets(t *testing.T) {
	r := testRegistry(t)
	w := testRequest(t, r, http.MethodPost, "/v1/mappings", testAdminToken, map[string]any{
		"endpointId": "alpha", "targetIP": "10.10.0.10", "targetPort": 22, "localPort": 10022,
	})
	testStatus(t, w, http.StatusCreated)
	m := testJSON[MappingView](t, w)
	stored := r.mappings[m.ID]
	if len(stored.Key) < 32 {
		t.Fatal("mapping key missing or unexpectedly short")
	}
	responses := []*httptest.ResponseRecorder{w, testRequest(t, r, http.MethodPatch, "/v1/mappings/"+m.ID, testAdminToken, map[string]bool{"enabled": false})}
	for _, response := range responses {
		for _, secret := range []string{testAdminToken, testAlphaToken, testBravoToken, stored.Key} {
			if strings.Contains(response.Body.String(), secret) {
				t.Fatal("mutation response contains a secret")
			}
		}
		var object map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &object); err != nil {
			t.Fatal(err)
		}
		if _, exists := object["key"]; exists {
			t.Fatal("mutation response exposes key field")
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("secret-bearing API responses must not be cached")
		}
		if response.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("missing nosniff header")
		}
	}
}

func TestRegistryTargetValidation(t *testing.T) {
	for _, tc := range []struct {
		name, endpoint, ip string
		target, local      int
	}{
		{"unknown endpoint", "unknown", "10.10.0.10", 22, 10022},
		{"hostname", "alpha", "localhost", 22, 10022},
		{"URL", "alpha", "http://10.10.0.10", 22, 10022},
		{"outside CIDR", "alpha", "10.11.0.10", 22, 10022},
		{"other endpoint CIDR", "alpha", "192.168.20.10", 22, 10022},
		{"loopback outside policy", "alpha", "127.0.0.1", 22, 10022},
		{"port outside policy", "alpha", "10.10.0.10", 3389, 10022},
		{"zero target port", "alpha", "10.10.0.10", 0, 10022},
		{"large target port", "alpha", "10.10.0.10", 65536, 10022},
		{"negative target port", "alpha", "10.10.0.10", -1, 10022},
		{"zero local port", "alpha", "10.10.0.10", 22, 0},
		{"large local port", "alpha", "10.10.0.10", 22, 65536},
		{"negative local port", "alpha", "10.10.0.10", 22, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := testRegistry(t)
			w := testRequest(t, r, http.MethodPost, "/v1/mappings", testAdminToken, map[string]any{
				"endpointId": tc.endpoint, "targetIP": tc.ip, "targetPort": tc.target, "localPort": tc.local,
			})
			testStatus(t, w, http.StatusBadRequest)
			if len(r.mappings) != 0 {
				t.Fatal("invalid mapping stored")
			}
		})
	}
	r := testRegistry(t)
	testCreate(t, r, "alpha", "2001:db8:1::10", 443, 10443)
}

func TestTargetAllowedLiteralAddressesAndPortPolicy(t *testing.T) {
	c := EndpointConfig{AllowedCIDRs: []string{"10.10.0.0/24", "2001:db8:1::/64"}, AllowedPorts: []int{22, 443}}
	for _, tc := range []struct {
		ip   string
		port int
		want bool
	}{
		{"10.10.0.1", 22, true}, {"10.10.0.255", 443, true}, {"2001:db8:1::2", 443, true},
		{"10.10.1.1", 22, false}, {"2001:db8:2::2", 443, false}, {"localhost", 22, false},
		{"10.10.0.1:22", 22, false}, {"10.10.0.1/32", 22, false}, {"[2001:db8:1::2]", 443, false},
		{"10.10.0.1", 23, false}, {"10.10.0.1", 0, false}, {"10.10.0.1", 65536, false},
		{"::ffff:10.10.0.1", 22, false}, {"", 22, false},
	} {
		t.Run(fmt.Sprintf("%s:%d", tc.ip, tc.port), func(t *testing.T) {
			if got := targetAllowed(Mapping{TargetIP: tc.ip, TargetPort: tc.port}, c); got != tc.want {
				t.Fatalf("targetAllowed = %v, want %v", got, tc.want)
			}
		})
	}
	c.AllowedPorts = nil
	for _, p := range []int{1, 65535} {
		if !targetAllowed(Mapping{TargetIP: "10.10.0.1", TargetPort: p}, c) {
			t.Fatalf("empty port allowlist rejected valid port %d", p)
		}
	}
	c.AllowedCIDRs = nil
	if targetAllowed(Mapping{TargetIP: "10.10.0.1", TargetPort: 22}, c) {
		t.Fatal("empty CIDR allowlist permits a target")
	}
}

func TestRegistryRejectsMalformedJSON(t *testing.T) {
	for _, body := range []string{
		`{"endpointId":"alpha","targetIP":"10.10.0.10","targetPort":22,"localPort":10022,"key":"attacker-supplied"}`,
		`{"endpointId":"alpha","targetIP":"10.10.0.10","targetPort":22,"localPort":10022} {}`,
		`{"endpointId":"alpha","targetIP":"10.10.0.10","targetPort":"22","localPort":10022}`,
		`null`, `[]`, ``, `{`,
	} {
		r := testRegistry(t)
		w := testRawRequest(t, r, http.MethodPost, "/v1/mappings", testAdminToken, body)
		testStatus(t, w, http.StatusBadRequest)
		if len(r.mappings) != 0 {
			t.Fatal("malformed request stored a mapping")
		}
	}
	r := testRegistry(t)
	m := testCreate(t, r, "alpha", "10.10.0.10", 22, 10022)
	for _, body := range []string{`{}`, `{"enabled":null}`, `{"enabled":"false"}`, `{"enabled":false,"targetIP":"127.0.0.1"}`} {
		w := testRawRequest(t, r, http.MethodPatch, "/v1/mappings/"+m.ID, testAdminToken, body)
		testStatus(t, w, http.StatusBadRequest)
		if !r.mappings[m.ID].Enabled {
			t.Fatal("invalid patch modified mapping")
		}
	}
	w := testRawRequest(t, r, http.MethodPost, "/v1/agent/poll", testAlphaToken, `{"reports":{},"endpointId":"bravo"}`)
	testStatus(t, w, http.StatusBadRequest)
	if !r.endpoints["alpha"].Seen.IsZero() {
		t.Fatal("invalid agent poll refreshed presence")
	}
}

func TestRegistryMappingLimit(t *testing.T) {
	c := testServerConfig()
	c.MaxMappings = 1
	r, err := NewRegistry(c)
	if err != nil {
		t.Fatal(err)
	}
	testCreate(t, r, "alpha", "10.10.0.10", 22, 10022)
	w := testRequest(t, r, http.MethodPost, "/v1/mappings", testAdminToken, map[string]any{"endpointId": "alpha", "targetIP": "10.10.0.11", "targetPort": 22, "localPort": 10023})
	testStatus(t, w, http.StatusConflict)
}

func TestRegistryConfigurationValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*ServerConfig)
	}{
		{"short admin token", func(c *ServerConfig) { c.AdminToken = "short" }},
		{"placeholder admin token", func(c *ServerConfig) { c.AdminToken = strings.Repeat("REPLACE", 6) }},
		{"short endpoint token", func(c *ServerConfig) { c.Endpoints[0].Token = "short" }},
		{"endpoint shares admin token", func(c *ServerConfig) { c.Endpoints[0].Token = c.AdminToken }},
		{"duplicate endpoint tokens", func(c *ServerConfig) { c.Endpoints[1].Token = c.Endpoints[0].Token }},
		{"duplicate endpoint IDs", func(c *ServerConfig) { c.Endpoints[1].ID = c.Endpoints[0].ID }},
		{"empty endpoint ID", func(c *ServerConfig) { c.Endpoints[0].ID = "" }},
		{"path endpoint ID", func(c *ServerConfig) { c.Endpoints[0].ID = "../../alpha" }},
		{"oversized endpoint ID", func(c *ServerConfig) { c.Endpoints[0].ID = strings.Repeat("x", 65) }},
		{"missing CIDR allowlist", func(c *ServerConfig) { c.Endpoints[0].AllowedCIDRs = nil }},
		{"invalid CIDR", func(c *ServerConfig) { c.Endpoints[0].AllowedCIDRs = []string{"10.10.0.1"} }},
		{"invalid allowed port", func(c *ServerConfig) { c.Endpoints[0].AllowedPorts = []int{0} }},
		{"too short lease", func(c *ServerConfig) { c.LeaseSeconds = 4 }},
		{"too long lease", func(c *ServerConfig) { c.LeaseSeconds = 121 }},
		{"negative mapping limit", func(c *ServerConfig) { c.MaxMappings = -1 }},
		{"excess mapping limit", func(c *ServerConfig) { c.MaxMappings = 1025 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testServerConfig()
			tc.mutate(&c)
			if _, err := NewRegistry(c); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	c := testServerConfig()
	c.LeaseSeconds = 0
	c.MaxMappings = 0
	r, err := NewRegistry(c)
	if err != nil {
		t.Fatal(err)
	}
	if r.lease != 15*time.Second || r.config.MaxMappings != 64 {
		t.Fatal("unexpected default limits")
	}
}

func TestCentralURLRequiresHTTPSExceptLiteralLoopback(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"https://control.example", "https://control.example"},
		{"https://control.example:9443/", "https://control.example:9443"},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"http://127.1.2.3:8080/", "http://127.1.2.3:8080"},
		{"http://[::1]:8080/", "http://[::1]:8080"},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := centralURL(tc.raw)
			if err != nil || got != tc.want {
				t.Fatalf("centralURL = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	for _, raw := range []string{
		"http://control.example", "http://localhost:8080", "http://192.168.1.10:8080", "http://0.0.0.0:8080",
		"http://127.0.0.1.example.com", "http://[::]:8080", "ftp://127.0.0.1", "//control.example", "https://",
		"https://user:password@control.example", "https://control.example/path", "https://control.example?token=secret",
		"https://control.example#fragment", "https://control.example/%2e%2e", "http://127.0.0.1@control.example",
	} {
		t.Run(raw, func(t *testing.T) {
			if got, err := centralURL(raw); err == nil {
				t.Fatalf("unsafe central URL accepted as %q", got)
			}
		})
	}
}

func TestAuthRequiresExactBearerValue(t *testing.T) {
	for _, header := range []string{"", testAdminToken, "bearer " + testAdminToken, "Bearer " + testAdminToken + " ", "Bearer " + testAdminToken + "extra"} {
		q := httptest.NewRequest(http.MethodPost, "/v1/admin/poll", bytes.NewReader(nil))
		q.Header.Set("Authorization", header)
		if auth(q, testAdminToken) {
			t.Fatalf("accepted incorrect authorization syntax %q", header)
		}
	}
	q := httptest.NewRequest(http.MethodPost, "/v1/admin/poll", nil)
	q.Header.Set("Authorization", "Bearer "+testAdminToken)
	if !auth(q, testAdminToken) {
		t.Fatal("valid bearer token rejected")
	}
}
