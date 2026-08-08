package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

// --- per-session webhook routing -----------------------------------------
// Each tenant has its own Odoo, so a single global URL would deliver every client's
// messages into one database.

func TestParseSessionHooks(t *testing.T) {
	got := parseSessionHooks(
		" acme=https://acme.example.com/hook|s1 , globex=https://globex.example.com/hook ,, bad , nourl= ")
	if len(got) != 2 {
		t.Fatalf("expected 2 routes, got %d: %v", len(got), got)
	}
	if got["acme"].url != "https://acme.example.com/hook" || got["acme"].secret != "s1" {
		t.Errorf("acme route wrong: %+v", got["acme"])
	}
	if got["globex"].url != "https://globex.example.com/hook" || got["globex"].secret != "" {
		t.Errorf("globex should inherit the global secret: %+v", got["globex"])
	}
	if len(parseSessionHooks("")) != 0 {
		t.Error("an empty setting must yield no routes")
	}
}

func TestRouteFor(t *testing.T) {
	odooWebhookURL = "https://shared.example.com/hook"
	webhookSecret = "GLOBAL"
	sessionHooks = parseSessionHooks(
		"acme=https://acme.example.com/hook|ACMESECRET,globex=https://globex.example.com/hook")
	t.Cleanup(func() {
		odooWebhookURL, webhookSecret = "", ""
		sessionHooks = map[string]webhookRoute{}
	})

	if r := routeFor("acme"); r.url != "https://acme.example.com/hook" || r.secret != "ACMESECRET" {
		t.Errorf("acme: %+v", r)
	}
	// A route with no secret of its own falls back to the global one.
	if r := routeFor("globex"); r.url != "https://globex.example.com/hook" || r.secret != "GLOBAL" {
		t.Errorf("globex: %+v", r)
	}
	// An unlisted session keeps the old single-Odoo behaviour.
	if r := routeFor("initech"); r.url != "https://shared.example.com/hook" || r.secret != "GLOBAL" {
		t.Errorf("initech should fall back: %+v", r)
	}
	// Crucially, one tenant's events never carry another tenant's secret.
	if routeFor("acme").secret == routeFor("initech").secret {
		t.Error("a per-session secret must not equal the global one")
	}
}

func TestNoRouteMeansNoDelivery(t *testing.T) {
	odooWebhookURL = ""
	webhookSecret = ""
	sessionHooks = map[string]webhookRoute{}
	t.Cleanup(func() { sessionHooks = map[string]webhookRoute{} })
	if routeFor("nobody").url != "" {
		t.Error("with nothing configured there must be no target")
	}
}

// Exercises the real delivery path — notifyOdoo -> queue -> worker -> postToOdoo — against two
// stand-in Odoo servers, which is the thing that actually matters: one tenant's WhatsApp events
// must never land in another tenant's database, nor carry its secret.
func TestWebhookRoutingDeliversEachTenantToItsOwnOdoo(t *testing.T) {
	type delivery struct{ secret, session string }
	acmeGot := make(chan delivery, 4)
	globexGot := make(chan delivery, 4)

	mk := func(sink chan delivery) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Session string `json:"session"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			sink <- delivery{secret: r.Header.Get("X-Webhook-Secret"), session: body.Session}
			w.WriteHeader(http.StatusOK)
		}))
	}
	acme, globex := mk(acmeGot), mk(globexGot)
	defer acme.Close()
	defer globex.Close()

	odooWebhookURL, webhookSecret = "", "GLOBAL"
	sessionHooks = parseSessionHooks(
		"acme=" + acme.URL + "|ACMESECRET,globex=" + globex.URL + "|GLOBEXSECRET")
	t.Cleanup(func() {
		odooWebhookURL, webhookSecret = "", ""
		sessionHooks = map[string]webhookRoute{}
	})

	startWebhookWorkers()
	notifyOdoo("acme", "message.received", map[string]any{"body": "for acme"})
	notifyOdoo("globex", "message.received", map[string]any{"body": "for globex"})

	recv := func(name string, ch chan delivery) delivery {
		t.Helper()
		select {
		case d := <-ch:
			return d
		case <-time.After(5 * time.Second):
			t.Fatalf("%s's Odoo received nothing", name)
			return delivery{}
		}
	}
	a, g := recv("acme", acmeGot), recv("globex", globexGot)

	if a.session != "acme" || a.secret != "ACMESECRET" {
		t.Errorf("acme delivery wrong: %+v", a)
	}
	if g.session != "globex" || g.secret != "GLOBEXSECRET" {
		t.Errorf("globex delivery wrong: %+v", g)
	}
	// Nothing crossed over.
	select {
	case extra := <-acmeGot:
		t.Errorf("acme's Odoo also received %+v — tenants are not isolated", extra)
	default:
	}
	select {
	case extra := <-globexGot:
		t.Errorf("globex's Odoo also received %+v — tenants are not isolated", extra)
	default:
	}
}
