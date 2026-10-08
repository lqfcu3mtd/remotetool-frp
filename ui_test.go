package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testUIToken = "ui-session-token-0123456789abcdef0123456789"
	testUIHost  = "127.0.0.1:8181"
)

type testRoundTripper func(*http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(q *http.Request) (*http.Response, error) { return f(q) }

func testUIRequest(t *testing.T, h http.Handler, method, path, host, origin, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	q := httptest.NewRequest(method, "http://"+testUIHost+path, strings.NewReader(body))
	q.Host = host
	if origin != "" {
		q.Header.Set("Origin", origin)
	}
	if token != "" {
		q.Header.Set("Authorization", "Bearer "+token)
	}
	q.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, q)
	return w
}

func TestUIRejectsForeignHostAndOrigin(t *testing.T) {
	r := &Runner{}
	h := r.UI(testUIToken, testUIHost)
	for _, tc := range []struct{ name, host, origin string }{
		{"foreign host", "evil.example:8181", ""},
		{"DNS rebinding host", "localhost:8181", ""},
		{"wrong port", "127.0.0.1:8182", ""},
		{"missing host", "", ""},
		{"foreign origin", testUIHost, "https://evil.example"},
		{"wrong origin port", testUIHost, "http://127.0.0.1:8182"},
		{"null origin", testUIHost, "null"},
		{"host suffix origin", testUIHost, "http://127.0.0.1:8181.evil.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, path := range []string{"/", "/api/state", "/api/v1/mappings"} {
				w := testUIRequest(t, h, http.MethodGet, path, tc.host, tc.origin, testUIToken, "")
				testStatus(t, w, http.StatusForbidden)
			}
		})
	}
	for _, origin := range []string{"", "http://" + testUIHost} {
		w := testUIRequest(t, h, http.MethodGet, "/api/state", testUIHost, origin, testUIToken, "")
		testStatus(t, w, http.StatusOK)
	}
}

func TestUIStateRequiresSessionTokenAndStripsAllKeys(t *testing.T) {
	secret := "secret-stcp-key-must-never-reach-browser"
	r := &Runner{Snapshot: Snapshot{Control: "online", Mappings: []MappingView{
		{Mapping: Mapping{ID: "active", EndpointID: "alpha", Key: secret, Enabled: true}},
		{Mapping: Mapping{ID: "disabled", EndpointID: "alpha", Key: secret + "-disabled", Enabled: false}},
	}}}
	h := r.UI(testUIToken, testUIHost)
	for _, token := range []string{"", "invalid", testAdminToken, testAlphaToken} {
		w := testUIRequest(t, h, http.MethodGet, "/api/state", testUIHost, "", token, "")
		testStatus(t, w, http.StatusUnauthorized)
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("unauthorized response leaked key")
		}
	}
	w := testUIRequest(t, h, http.MethodGet, "/api/state", testUIHost, "", testUIToken, "")
	testStatus(t, w, http.StatusOK)
	if strings.Contains(w.Body.String(), secret) || strings.Contains(w.Body.String(), `"key"`) {
		t.Fatal("UI state leaked mapping key from raw snapshot")
	}
	s := testJSON[Snapshot](t, w)
	if len(s.Mappings) != 2 {
		t.Fatal("redaction lost mappings")
	}
	for _, m := range s.Mappings {
		if m.Key != "" {
			t.Fatal("key present after redaction")
		}
	}
	// The UI must redact its response without mutating the supervisor's raw snapshot.
	if r.Snapshot.Mappings[0].Key != secret || r.Snapshot.Mappings[1].Key != secret+"-disabled" {
		t.Fatal("UI mutated runner snapshot during redaction")
	}
}

func TestUIHTMLContainsNoCredentials(t *testing.T) {
	r := &Runner{Config: ClientConfig{Token: testAdminToken}, Snapshot: Snapshot{Mappings: []MappingView{{Mapping: Mapping{Key: "hidden-mapping-key"}}}}}
	h := r.UI(testUIToken, testUIHost)
	w := testUIRequest(t, h, http.MethodGet, "/", testUIHost, "", "", "")
	testStatus(t, w, http.StatusOK)
	for _, secret := range []string{testUIToken, testAdminToken, testAlphaToken, testBravoToken, "hidden-mapping-key"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("HTML contains a credential")
		}
	}
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatal("root is not HTML")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("UI may be cached")
	}
	if w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("UI may leak referrer")
	}
	csp := w.Header().Get("Content-Security-Policy")
	for _, directive := range []string{"frame-ancestors 'none'", "connect-src 'self'", "base-uri 'none'", "form-action 'none'"} {
		if !strings.Contains(csp, directive) {
			t.Fatalf("missing CSP directive %s", directive)
		}
	}
	if strings.Contains(w.Body.String(), "localStorage") || strings.Contains(w.Body.String(), "sessionStorage") {
		t.Fatal("UI persists credential in browser storage")
	}
}

func TestUIMutationsRequireTokenAndOnlyForwardMappingActions(t *testing.T) {
	calls := 0
	var lastMethod, lastPath, lastAuth, lastBody string
	r := &Runner{API: &APIClient{Base: "https://central.example", Token: testAdminToken, HTTP: &http.Client{Transport: testRoundTripper(func(q *http.Request) (*http.Response, error) {
		calls++
		lastMethod, lastPath, lastAuth = q.Method, q.URL.Path, q.Header.Get("Authorization")
		if q.Body != nil {
			b, err := io.ReadAll(q.Body)
			if err != nil {
				t.Fatal(err)
			}
			lastBody = string(b)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
	})}}}
	h := r.UI(testUIToken, testUIHost)
	for _, route := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/mappings", `{"endpointId":"alpha","targetIP":"10.10.0.10","targetPort":22,"localPort":10022}`},
		{http.MethodPatch, "/api/v1/mappings/mapping-id", `{"enabled":false}`},
		{http.MethodDelete, "/api/v1/mappings/mapping-id", ""},
	} {
		for _, token := range []string{"", "wrong", testAdminToken, testAlphaToken} {
			before := calls
			w := testUIRequest(t, h, route.method, route.path, testUIHost, "", token, route.body)
			testStatus(t, w, http.StatusUnauthorized)
			if calls != before {
				t.Fatal("unauthorized UI request reached central API")
			}
		}
		before := calls
		w := testUIRequest(t, h, route.method, route.path, testUIHost, "http://"+testUIHost, testUIToken, route.body)
		testStatus(t, w, http.StatusOK)
		if calls != before+1 || lastMethod != route.method || lastPath != strings.TrimPrefix(route.path, "/api") {
			t.Fatal("mapping action not forwarded as expected")
		}
		if lastAuth != "Bearer "+testAdminToken {
			t.Fatal("central API did not use its scoped admin token")
		}
		if route.body != "" && lastBody != route.body {
			t.Fatalf("forwarded body = %s, want %s", lastBody, route.body)
		}
	}
	for _, path := range []string{"/api/v1/admin/poll", "/api/v1/agent/poll", "/api/arbitrary", "/api/state"} {
		before := calls
		w := testUIRequest(t, h, http.MethodPost, path, testUIHost, "", testUIToken, `{}`)
		testStatus(t, w, http.StatusNotFound)
		if calls != before {
			t.Fatal("non-mapping action reached central API")
		}
	}
	before := calls
	w := testUIRequest(t, h, http.MethodPost, "/api/v1/mappings", testUIHost, "", testUIToken, `{} {}`)
	testStatus(t, w, http.StatusBadRequest)
	if calls != before {
		t.Fatal("malformed mutation reached central API")
	}
}

func TestManagementServerRequiresTLSOutsideLiteralLoopback(t *testing.T) {
	// The deliberately invalid admin token stops run() after its listen/TLS guard,
	// so these tests never bind a network listener or enter the serving loop.
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	for _, tc := range []struct {
		name, listen, cert, key string
		wantTLSReject           bool
	}{
		{"wildcard IPv4", "0.0.0.0:0", "", "", true},
		{"wildcard IPv6", "[::]:0", "", "", true},
		{"empty host", ":0", "", "", true},
		{"LAN address", "192.0.2.10:0", "", "", true},
		{"localhost hostname", "localhost:0", "", "", true},
		{"certificate without key", "0.0.0.0:0", "server.pem", "", true},
		{"key without certificate", "0.0.0.0:0", "", "server.key", true},
		{"IPv4 loopback", "127.0.0.1:0", "", "", false},
		{"IPv6 loopback", "[::1]:0", "", "", false},
		{"default listen", "", "", "", false},
		{"TLS provided", "0.0.0.0:0", "server.pem", "server.key", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := ServerConfig{Listen: tc.listen, TLSCert: tc.cert, TLSKey: tc.key, AdminToken: "short"}
			b, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "server.json")
			if err = os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			os.Args = []string{"remotetool", "server", "-config", path}
			err = run()
			if err == nil {
				t.Fatal("expected validation failure before listening")
			}
			if tc.wantTLSReject {
				if !strings.Contains(err.Error(), "requires tlsCert and tlsKey") {
					t.Fatalf("wrong validation failure: %v", err)
				}
			} else if !strings.Contains(err.Error(), "adminToken") {
				t.Fatalf("TLS guard rejected allowed configuration: %v", err)
			}
		})
	}
}

func TestAPIClientRefusesRedirects(t *testing.T) {
	client, err := newAPI(ClientConfig{CentralURL: "https://central.example", Token: testAdminToken})
	if err != nil {
		t.Fatal(err)
	}
	if client.HTTP.CheckRedirect == nil {
		t.Fatal("central client may follow credential-bearing redirects")
	}
	q := httptest.NewRequest(http.MethodPost, "https://other.example/v1/admin/poll", nil)
	if err = client.HTTP.CheckRedirect(q, nil); err == nil {
		t.Fatal("redirect accepted")
	}
}

func TestAPIClientDoesNotExposeTransportErrors(t *testing.T) {
	client := &APIClient{Base: "https://central.example", Token: testAdminToken, HTTP: &http.Client{Transport: testRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, context.Canceled
	})}}
	var out any
	err := client.call(context.Background(), http.MethodPost, "/v1/admin/poll", nil, &out)
	if err == nil || err.Error() != "central request failed" {
		t.Fatalf("transport error not safely bounded: %v", err)
	}
}
