package main

import (
	"bytes"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

// fakeDeps is an in-memory server: a KV store with expiry on the test clock, a mailbox and a log.
type fakeDeps struct {
	now      *time.Time
	kv       map[string]fakeEntry
	mails    []sentMail
	logs     []string
	mailErr  error
	settings serverSettings
}

type fakeEntry struct {
	value     []byte
	expiresAt time.Time
}

type sentMail struct{ to, subject, body string }

func newFakeDeps(now *time.Time) *fakeDeps {
	return &fakeDeps{
		now:      now,
		kv:       map[string]fakeEntry{},
		settings: serverSettings{SiteURL: "https://chat.example.com", SiteName: "Example Chat", IsMFAEnabled: true},
	}
}

func (f *fakeDeps) live(key string) (fakeEntry, bool) {
	e, ok := f.kv[key]
	if ok && !f.now.Before(e.expiresAt) {
		delete(f.kv, key)
		return fakeEntry{}, false
	}
	return e, ok
}

func (f *fakeDeps) kvGet(key string) ([]byte, error) {
	e, _ := f.live(key)
	return e.value, nil
}

func (f *fakeDeps) kvSet(key string, value []byte, ttl time.Duration) error {
	f.kv[key] = fakeEntry{value: value, expiresAt: f.now.Add(ttl)}
	return nil
}

func (f *fakeDeps) kvSetIfAbsent(key string, value []byte, ttl time.Duration) (bool, error) {
	if _, ok := f.live(key); ok {
		return false, nil
	}
	return true, f.kvSet(key, value, ttl)
}

func (f *fakeDeps) kvCompareAndDelete(key string, oldValue []byte) (bool, error) {
	e, ok := f.live(key)
	if !ok || !bytes.Equal(e.value, oldValue) {
		return false, nil
	}
	delete(f.kv, key)
	return true, nil
}

func (f *fakeDeps) kvDelete(key string) error {
	delete(f.kv, key)
	return nil
}

func (f *fakeDeps) sendMail(to, subject, body string) error {
	if f.mailErr != nil {
		return f.mailErr
	}
	f.mails = append(f.mails, sentMail{to, subject, body})
	return nil
}

func (f *fakeDeps) server() serverSettings { return f.settings }

func (f *fakeDeps) logInfo(msg string, kv ...any) {
	f.logs = append(f.logs, fmt.Sprint(append([]any{msg}, kv...)...))
}
func (f *fakeDeps) logError(msg string, kv ...any) { f.logInfo("ERROR "+msg, kv...) }

// harness wires a Plugin to fakeDeps and a controllable clock.
type harness struct {
	t      *testing.T
	now    time.Time
	deps   *fakeDeps
	plugin *Plugin
}

func newHarness(t *testing.T, exempt string) *harness {
	h := &harness{t: t, now: time.Date(2026, 11, 15, 3, 0, 0, 0, time.UTC)}
	h.deps = newFakeDeps(&h.now)
	cfg := &configuration{ApprovalWindowMinutes: 15, EmailRateLimitMinutes: 2, ExemptUsernames: exempt}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	cfg.exemptUsernames = parseExemptUsernames(exempt)
	counter := byte(0)
	h.plugin = &Plugin{configuration: cfg}
	h.plugin.gate = &gate{
		deps: h.deps,
		cfg:  h.plugin.getConfiguration,
		now:  func() time.Time { return h.now },
		random: func(b []byte) (int, error) {
			counter++
			for i := range b {
				b[i] = counter
			}
			return len(b), nil
		},
	}
	return h
}

var (
	alice   = &model.User{Id: "aliceid", Username: "alice", Email: "alice@example.com"}
	laptop  = attempt{IP: "203.0.113.7", UserAgent: "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0"}
	phone   = attempt{IP: "203.0.113.7", UserAgent: "Mattermost Mobile/2.30.0 (iOS 18)"}
	elsewhr = attempt{IP: "198.51.100.9", UserAgent: laptop.UserAgent}
)

func (h *harness) login(u *model.User, at attempt) string {
	return h.plugin.UserWillLogIn(&plugin.Context{IPAddress: at.IP, UserAgent: at.UserAgent}, u)
}

var linkRE = regexp.MustCompile(`href="([^"]+/approve\?token=[^"]+)"`)

// lastLink returns the approval link from the newest email.
func (h *harness) lastLink() *url.URL {
	h.t.Helper()
	if len(h.deps.mails) == 0 {
		h.t.Fatal("no email sent")
	}
	m := linkRE.FindStringSubmatch(h.deps.mails[len(h.deps.mails)-1].body)
	if m == nil {
		h.t.Fatal("no approval link in email")
	}
	u, err := url.Parse(html.UnescapeString(m[1]))
	if err != nil {
		h.t.Fatal(err)
	}
	return u
}

// get fetches the confirmation page and returns the response and the CSRF cookie it set.
func (h *harness) get(link *url.URL) (*httptest.ResponseRecorder, *http.Cookie) {
	r := httptest.NewRequest(http.MethodGet, "/approve?"+link.RawQuery, nil)
	w := httptest.NewRecorder()
	h.plugin.ServeHTTP(&plugin.Context{IPAddress: "192.0.2.1"}, w, r)
	for _, c := range w.Result().Cookies() {
		if c.Name == csrfCookie {
			return w, c
		}
	}
	return w, nil
}

// post submits the Approve form with the given token, form CSRF value and cookie.
func (h *harness) post(token, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
	form := url.Values{"token": {token}, "csrf": {csrf}}
	r := httptest.NewRequest(http.MethodPost, "/approve", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.plugin.ServeHTTP(&plugin.Context{IPAddress: "192.0.2.1"}, w, r)
	return w
}

var csrfRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// approveLast walks the emailed link through GET and POST, as a browser would.
func (h *harness) approveLast() *httptest.ResponseRecorder {
	h.t.Helper()
	link := h.lastLink()
	w, cookie := h.get(link)
	if w.Code != http.StatusOK || cookie == nil {
		h.t.Fatalf("GET: status %d, cookie %v", w.Code, cookie)
	}
	m := csrfRE.FindStringSubmatch(w.Body.String())
	if m == nil {
		h.t.Fatal("no csrf field on page")
	}
	return h.post(link.Query().Get("token"), m[1], cookie)
}

func TestBotsTOTPAndExemptUsersPass(t *testing.T) {
	h := newHarness(t, " Dave , erin")
	cases := map[string]*model.User{
		"bot":         {Id: "b", Username: "bot", IsBot: true},
		"totp":        {Id: "m", Username: "mfa", MfaActive: true},
		"exempt case": {Id: "d", Username: "dave"},
	}
	for name, u := range cases {
		if got := h.login(u, laptop); got != "" {
			t.Errorf("%s: rejected with %q", name, got)
		}
	}
	if len(h.deps.mails) != 0 {
		t.Errorf("sent %d emails, want 0", len(h.deps.mails))
	}
}

func TestTOTPUserNeedsApprovalWhenServerMFAIsOff(t *testing.T) {
	h := newHarness(t, "")
	h.deps.settings.IsMFAEnabled = false
	if got := h.login(&model.User{Id: "m", Username: "mfa", Email: "m@x", MfaActive: true}, laptop); got == "" {
		t.Fatal("MfaActive user allowed although the server never checked a TOTP code")
	}
}

func TestRejectsAndEmailsOnceWithinRateLimit(t *testing.T) {
	h := newHarness(t, "")
	if got := h.login(alice, laptop); got != rejectionReason {
		t.Fatalf("got %q, want rejection", got)
	}
	if len(h.deps.mails) != 1 {
		t.Fatalf("sent %d emails, want 1", len(h.deps.mails))
	}
	m := h.deps.mails[0]
	for _, want := range []string{"alice@example.com", laptop.IP, "Firefox/140.0", "Profile &gt; Security", "15 minutes", "Sun 15 Nov 2026, 03:00:00 UTC"} {
		if !strings.Contains(m.to+m.body, want) {
			t.Errorf("email lacks %q", want)
		}
	}
	token := h.lastLink().Query().Get("token")
	for k, e := range h.deps.kv {
		if strings.Contains(k, token) || bytes.Contains(e.value, []byte(token)) {
			t.Errorf("raw token stored in KV under %s", k)
		}
	}

	h.now = h.now.Add(119 * time.Second)
	if got := h.login(alice, laptop); got != rejectionReason {
		t.Fatalf("second attempt: got %q", got)
	}
	if len(h.deps.mails) != 1 {
		t.Fatalf("rate limit broken: %d emails", len(h.deps.mails))
	}
	h.now = h.now.Add(2 * time.Second)
	h.login(alice, laptop)
	if len(h.deps.mails) != 2 {
		t.Fatalf("after the rate limit: %d emails, want 2", len(h.deps.mails))
	}
}

func TestGetDoesNotApproveAndPostApprovesOnce(t *testing.T) {
	h := newHarness(t, "")
	h.login(alice, laptop)
	link := h.lastLink()

	w, _ := h.get(link)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), laptop.IP) {
		t.Fatalf("GET: %d %s", w.Code, w.Body.String())
	}
	h.now = h.now.Add(3 * time.Minute)
	if got := h.login(alice, laptop); got == "" {
		t.Fatal("GET alone approved the login")
	}

	if w := h.approveLast(); w.Code != http.StatusOK {
		t.Fatalf("POST: %d %s", w.Code, w.Body.String())
	}
	if got := h.login(alice, phone); got == "" {
		t.Error("approval for one user agent admitted another")
	}
	if got := h.login(alice, elsewhr); got == "" {
		t.Error("approval for one IP admitted another")
	}
	if got := h.login(alice, laptop); got != "" {
		t.Fatalf("approved login rejected: %q", got)
	}
	if got := h.login(alice, laptop); got == "" {
		t.Error("approval was used twice")
	}
}

func TestPostNeedsMatchingCSRFCookie(t *testing.T) {
	h := newHarness(t, "")
	h.login(alice, laptop)
	link := h.lastLink()
	token := link.Query().Get("token")
	w, cookie := h.get(link)
	csrf := csrfRE.FindStringSubmatch(w.Body.String())[1]

	if w := h.post(token, csrf, nil); w.Code != http.StatusForbidden {
		t.Errorf("no cookie: %d, want 403", w.Code)
	}
	if w := h.post(token, "forged", cookie); w.Code != http.StatusForbidden {
		t.Errorf("mismatched form value: %d, want 403", w.Code)
	}
	if w := h.post(token, csrf, cookie); w.Code != http.StatusOK {
		t.Fatalf("valid POST: %d", w.Code)
	}
	if w := h.post(token, csrf, cookie); w.Code != http.StatusGone {
		t.Errorf("reused token: %d, want 410", w.Code)
	}
}

func TestExpiredTokenAndStaleApprovalAreRefused(t *testing.T) {
	h := newHarness(t, "")
	h.login(alice, laptop)
	link := h.lastLink()
	h.now = h.now.Add(15*time.Minute + time.Second)
	if w, _ := h.get(link); w.Code != http.StatusGone || !strings.Contains(w.Body.String(), "expired") {
		t.Fatalf("expired GET: %d", w.Code)
	}

	h.login(alice, laptop)
	if w := h.approveLast(); w.Code != http.StatusOK {
		t.Fatalf("POST: %d", w.Code)
	}
	h.now = h.now.Add(15*time.Minute + time.Second)
	if got := h.login(alice, laptop); got == "" {
		t.Fatal("approval older than the window was honoured")
	}
}

func TestMailFailureRejectsAndClearsRateLimit(t *testing.T) {
	h := newHarness(t, "")
	h.deps.mailErr = errors.New("smtp down")
	if got := h.login(alice, laptop); got != rejectionReason {
		t.Fatalf("got %q", got)
	}
	if len(h.deps.kv) != 0 {
		t.Errorf("left %d KV entries after a failed email", len(h.deps.kv))
	}
	h.deps.mailErr = nil
	h.login(alice, laptop)
	if len(h.deps.mails) != 1 {
		t.Fatalf("retry after failure sent %d emails, want 1", len(h.deps.mails))
	}
}

func TestLogsNameUserIPAndAgentButNoToken(t *testing.T) {
	h := newHarness(t, "")
	h.login(alice, laptop)
	token := h.lastLink().Query().Get("token")
	h.login(alice, laptop)
	h.approveLast()
	h.login(alice, laptop)
	all := strings.Join(h.deps.logs, "\n")
	for _, want := range []string{"approval email sent", "already sent within the rate limit", "Sign-in approved", "allowed by emailed approval", laptop.IP, laptop.UserAgent, "alice"} {
		if !strings.Contains(all, want) {
			t.Errorf("logs lack %q:\n%s", want, all)
		}
	}
	if strings.Contains(all, token) {
		t.Error("token written to the log")
	}
}

func TestConfigurationValidation(t *testing.T) {
	for _, c := range []configuration{{ApprovalWindowMinutes: 0, EmailRateLimitMinutes: 2}, {ApprovalWindowMinutes: 15, EmailRateLimitMinutes: 0}} {
		if c.validate() == nil {
			t.Errorf("%+v accepted", c)
		}
	}
	if got := parseExemptUsernames(" A, ,b "); len(got) != 2 || !got["a"] || !got["b"] {
		t.Errorf("parse: %v", got)
	}
}

func TestOtherPathsAndMethods(t *testing.T) {
	h := newHarness(t, "")
	w := httptest.NewRecorder()
	h.plugin.ServeHTTP(&plugin.Context{}, w, httptest.NewRequest(http.MethodGet, "/other", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown path: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.plugin.ServeHTTP(&plugin.Context{}, w, httptest.NewRequest(http.MethodPut, "/approve", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT: %d", w.Code)
	}
	if w, _ := h.get(&url.URL{RawQuery: "token=nonsense"}); w.Code != http.StatusGone {
		t.Errorf("unknown token: %d", w.Code)
	}
}
