package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The middleware is the only thing standing between a tenant and every other tenant's
// WhatsApp number, so each branch gets a case.

func TestSessionFromPath(t *testing.T) {
	for path, want := range map[string]string{
		"/sessions/acme/send":       "acme",
		"/sessions/acme/media/AB12": "acme",
		"/sessions/acme/start":      "acme",
		"/sessions":                 "", // the listing is not scoped to one session
		"/sessions/acme":            "", // ditto: no action segment
		"/health":                   "",
		"/":                         "",
		"//send":                    "",
	} {
		if got := sessionFromPath(path); got != want {
			t.Errorf("sessionFromPath(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestParseSessionKeys(t *testing.T) {
	got := parseSessionKeys(" acme:tok1 , globex:tok2 ,, bad , :notok , noval: ")
	if len(got) != 2 {
		t.Fatalf("expected 2 usable pairs, got %d: %v", len(got), got)
	}
	if got["acme"] != "tok1" || got["globex"] != "tok2" {
		t.Errorf("unexpected map: %v", got)
	}
	if len(parseSessionKeys("")) != 0 {
		t.Error("an empty setting must yield no keys, not a nil-map panic")
	}
}

func serve(t *testing.T, method, path string, headers map[string]string) int {
	t.Helper()
	reached := false
	h := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK && !reached {
		t.Fatal("200 without reaching the handler")
	}
	return rec.Code
}

func TestAuthMiddleware(t *testing.T) {
	apiKey = "ADMIN"
	sessionKeys = map[string]string{"acme": "ACMEKEY"}
	t.Cleanup(func() { apiKey = ""; sessionKeys = map[string]string{} })

	cases := []struct {
		name    string
		method  string
		path    string
		headers map[string]string
		want    int
	}{
		{"health needs no key", "GET", "/health", nil, 200},
		{"no key at all", "POST", "/sessions/acme/send", nil, 401},
		{"wrong key", "POST", "/sessions/acme/send", map[string]string{"X-Api-Key": "nope"}, 401},
		{"admin key", "POST", "/sessions/acme/send", map[string]string{"X-Api-Key": "ADMIN"}, 200},
		{"admin key, any session", "POST", "/sessions/globex/send", map[string]string{"X-Api-Key": "ADMIN"}, 200},
		{"admin key lists sessions", "GET", "/sessions", map[string]string{"X-Api-Key": "ADMIN"}, 200},
		{"bearer is accepted", "POST", "/sessions/acme/send", map[string]string{"Authorization": "Bearer ADMIN"}, 200},

		// The point of the change: a session key is confined to its own session.
		{"session key, own session", "POST", "/sessions/acme/send", map[string]string{"X-Api-Key": "ACMEKEY"}, 200},
		{"session key, own media", "GET", "/sessions/acme/media/AB12", map[string]string{"X-Api-Key": "ACMEKEY"}, 200},
		{"session key, ANOTHER session", "POST", "/sessions/globex/send", map[string]string{"X-Api-Key": "ACMEKEY"}, 401},
		{"session key cannot list sessions", "GET", "/sessions", map[string]string{"X-Api-Key": "ACMEKEY"}, 401},
		{"session key for an unconfigured session", "POST", "/sessions/initech/send", map[string]string{"X-Api-Key": "ACMEKEY"}, 401},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := serve(t, c.method, c.path, c.headers); got != c.want {
				t.Errorf("%s %s = %d, want %d", c.method, c.path, got, c.want)
			}
		})
	}
}

func TestEmptyKeysLockEverythingOut(t *testing.T) {
	// A misconfigured gateway must refuse, never fall open.
	apiKey = ""
	sessionKeys = map[string]string{}
	t.Cleanup(func() { apiKey = "" })
	if got := serve(t, "POST", "/sessions/acme/send", map[string]string{"X-Api-Key": ""}); got != 401 {
		t.Errorf("empty presented + empty configured key = %d, want 401", got)
	}
	if got := serve(t, "POST", "/sessions/acme/send", nil); got != 401 {
		t.Errorf("no header at all = %d, want 401", got)
	}
}
