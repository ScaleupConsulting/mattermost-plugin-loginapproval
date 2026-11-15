package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

// fakeDeps is an in-memory server: a KV store with expiry on the test clock, a mailbox and a log.
type fakeDeps struct {
	now      *time.Time
	kv       map[string]time.Time // key -> expiry
	mails    []sentMail
	logs     []string
	mailErr  error
	settings serverSettings
}

type sentMail struct{ to, subject, body string }

func (f *fakeDeps) kvSetIfAbsent(key string, _ []byte, ttl time.Duration) (bool, error) {
	if expiresAt, ok := f.kv[key]; ok && f.now.Before(expiresAt) {
		return false, nil
	}
	f.kv[key] = f.now.Add(ttl)
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

// cutoff is the production value chosen for chat.scaleupconsulting.com.au: 09:00 Sydney on 29 Nov 2026.
const cutoff = "2026-11-28T22:00:00Z"

// harness wires a gate to fakeDeps and a controllable clock.
type harness struct {
	t    *testing.T
	now  time.Time
	deps *fakeDeps
	gate *gate
}

func newHarness(t *testing.T, exempt string) *harness {
	t.Helper()
	at, err := parseTOTPRequiredFrom(cutoff)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &configuration{TOTPRequiredFrom: cutoff, ExemptUsernames: exempt, totpRequiredFrom: at, exemptUsernames: parseExemptUsernames(exempt)}
	h := &harness{t: t, now: at.Add(-7 * 24 * time.Hour)}
	h.deps = &fakeDeps{
		now:      &h.now,
		kv:       map[string]time.Time{},
		settings: serverSettings{SiteURL: "https://chat.example.com", SiteName: "Example Chat", IsMFAEnabled: true},
	}
	h.gate = &gate{deps: h.deps, cfg: func() *configuration { return cfg }, now: func() time.Time { return h.now }}
	return h
}

func (h *harness) setNow(t time.Time) { h.now = t }

func (h *harness) login(u *model.User) string {
	return h.gate.check(u, attempt{IP: "203.0.113.7", UserAgent: "Mozilla/5.0 Firefox/140.0"})
}

func user(name string) *model.User {
	return &model.User{Id: name + "-id", Username: name, Email: name + "@example.com"}
}

// sydneyUser has a manual Australia/Sydney timezone, as set in Settings > Display > Timezone.
func sydneyUser(name string) *model.User {
	u := user(name)
	u.Timezone = model.StringMap{"useAutomaticTimezone": "false", "manualTimezone": "Australia/Sydney", "automaticTimezone": ""}
	return u
}

func (h *harness) cutoff() time.Time { return h.gate.cfg().totpRequiredFrom }

func TestBotsTOTPAndExemptUsersPassWithoutEmail(t *testing.T) {
	h := newHarness(t, " Dave , erin")
	bot := user("bot1")
	bot.IsBot = true
	mfa := user("mfa")
	mfa.MfaActive = true
	for _, now := range []time.Time{h.cutoff().Add(-time.Hour), h.cutoff(), h.cutoff().Add(30 * 24 * time.Hour)} {
		h.setNow(now)
		for _, u := range []*model.User{bot, mfa, user("dave"), user("ERIN")} {
			if got := h.login(u); got != "" {
				t.Errorf("%s at %s: rejected with %q", u.Username, now, got)
			}
		}
	}
	if len(h.deps.mails) != 0 {
		t.Errorf("sent %d emails, want 0", len(h.deps.mails))
	}
}

func TestTOTPUserIsRefusedAfterCutoffWhenServerMFAIsOff(t *testing.T) {
	h := newHarness(t, "")
	h.deps.settings.IsMFAEnabled = false
	h.setNow(h.cutoff())
	mfa := user("mfa")
	mfa.MfaActive = true
	if got := h.login(mfa); got != rejectionReason {
		t.Errorf("got %q: the server checked no code, so MfaActive proves nothing", got)
	}
}

func TestBeforeCutoffAllowsAndRemindsOncePerDay(t *testing.T) {
	h := newHarness(t, "")
	alice := sydneyUser("alice")
	if got := h.login(alice); got != "" {
		t.Fatalf("rejected before the cutoff: %q", got)
	}
	h.now = h.now.Add(23 * time.Hour)
	if got := h.login(alice); got != "" {
		t.Fatalf("second login rejected: %q", got)
	}
	if len(h.deps.mails) != 1 {
		t.Fatalf("sent %d emails within 24h, want 1", len(h.deps.mails))
	}
	m := h.deps.mails[0]
	if m.to != "alice@example.com" {
		t.Errorf("to %q", m.to)
	}
	wantCutoff := "Sun 29 Nov 2026, 09:00 AEDT"
	if !strings.Contains(m.subject, wantCutoff) || !strings.Contains(m.body, wantCutoff) {
		t.Errorf("subject %q or body lacks %q", m.subject, wantCutoff)
	}
	for _, want := range []string{"https://chat.example.com", "<b>Profile</b>", "<b>Security</b>", "<b>Add MFA to Account</b>", "cannot turn multi-factor authentication on"} {
		if !strings.Contains(m.body, want) {
			t.Errorf("reminder lacks %q", want)
		}
	}
	h.now = h.now.Add(time.Hour)
	h.login(alice)
	if len(h.deps.mails) != 2 {
		t.Errorf("sent %d emails after 24h, want 2", len(h.deps.mails))
	}
}

func TestReminderShowsCutoffInUTCWithoutTimezone(t *testing.T) {
	h := newHarness(t, "")
	h.login(user("bob"))
	want := "Sat 28 Nov 2026, 22:00 UTC"
	if len(h.deps.mails) != 1 || !strings.Contains(h.deps.mails[0].body, want) {
		t.Fatalf("want one reminder naming %q, got %+v", want, h.deps.mails)
	}
}

func TestCutoffIsInclusive(t *testing.T) {
	h := newHarness(t, "")
	h.setNow(h.cutoff().Add(-time.Second))
	if got := h.login(user("alice")); got != "" {
		t.Errorf("one second before the cutoff: rejected with %q", got)
	}
	h.setNow(h.cutoff())
	if got := h.login(user("bob")); got != rejectionReason {
		t.Errorf("at the cutoff: got %q", got)
	}
}

func TestAfterCutoffRejectsAndExplainsOncePerDay(t *testing.T) {
	h := newHarness(t, "")
	alice := sydneyUser("alice")
	h.setNow(h.cutoff().Add(-time.Minute))
	h.login(alice) // a reminder just before the cutoff must not hold back the refusal email
	h.setNow(h.cutoff().Add(time.Minute))
	for range 3 {
		if got := h.login(alice); got != rejectionReason {
			t.Fatalf("after the cutoff: got %q", got)
		}
	}
	if len(h.deps.mails) != 2 {
		t.Fatalf("sent %d emails, want a reminder then one refusal", len(h.deps.mails))
	}
	m := h.deps.mails[1]
	for _, want := range []string{"needs multi-factor authentication", "Sun 29 Nov 2026, 09:00 AEDT", "203.0.113.7", "Firefox/140.0",
		"said the email, username or password was invalid", "where you are still signed in", "exempt list", "<b>Add MFA to Account</b>"} {
		if !strings.Contains(m.subject+m.body, want) {
			t.Errorf("refusal email lacks %q", want)
		}
	}
	h.now = h.now.Add(24 * time.Hour)
	h.login(alice)
	if len(h.deps.mails) != 3 {
		t.Errorf("sent %d emails after another 24h, want 3", len(h.deps.mails))
	}
}

func TestMailFailureKeepsDecisionAndClearsRateLimit(t *testing.T) {
	h := newHarness(t, "")
	h.deps.mailErr = errors.New("smtp down")
	if got := h.login(user("alice")); got != "" {
		t.Errorf("before the cutoff a mail failure must not block the login: %q", got)
	}
	h.setNow(h.cutoff())
	if got := h.login(user("alice")); got != rejectionReason {
		t.Errorf("after the cutoff a mail failure must still reject: %q", got)
	}
	h.deps.mailErr = nil
	h.login(user("alice"))
	if len(h.deps.mails) != 1 {
		t.Errorf("sent %d emails after mail recovered, want 1 (the failed send must not hold the rate limit)", len(h.deps.mails))
	}
}

func TestLogsNameUserIPAndAgent(t *testing.T) {
	h := newHarness(t, "")
	h.login(user("alice"))
	h.setNow(h.cutoff())
	h.login(user("alice"))
	if len(h.deps.logs) != 2 {
		t.Fatalf("got %d log lines, want 2: %q", len(h.deps.logs), h.deps.logs)
	}
	for _, line := range h.deps.logs {
		for _, want := range []string{"alice", "203.0.113.7", "Firefox/140.0"} {
			if !strings.Contains(line, want) {
				t.Errorf("log %q lacks %q", line, want)
			}
		}
	}
}

func TestParseTOTPRequiredFrom(t *testing.T) {
	for _, bad := range []string{"", "  ", "2026-11-29", "2026-11-29 09:00", "2026-11-29T09:00:00+11:00", "tomorrow"} {
		if _, err := parseTOTPRequiredFrom(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	got, err := parseTOTPRequiredFrom(" " + cutoff + " ")
	if err != nil || !got.Equal(time.Date(2026, 11, 28, 22, 0, 0, 0, time.UTC)) {
		t.Errorf("got %v, %v", got, err)
	}
}

func TestOnActivateRefusesWithoutCutoff(t *testing.T) {
	api := emptyConfigAPI{}
	p := &Plugin{}
	p.SetAPI(api)
	err := p.OnActivate()
	if err == nil || !strings.Contains(err.Error(), "TOTPRequiredFrom") {
		t.Errorf("got %v, want a refusal naming TOTPRequiredFrom", err)
	}
}

// emptyConfigAPI is a server whose plugin settings were never saved; any other API call panics.
type emptyConfigAPI struct{ plugin.API }

func (emptyConfigAPI) LoadPluginConfiguration(any) error { return nil }
