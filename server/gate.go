package main

import (
	"errors"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
)

// deps is everything the gate needs from the server, so tests can run it without one.
type deps interface {
	kvSetIfAbsent(key string, value []byte, ttl time.Duration) (bool, error)
	kvDelete(key string) error
	sendMail(to, subject, htmlBody string) error
	server() serverSettings
	logInfo(msg string, keyValuePairs ...any)
	logError(msg string, keyValuePairs ...any)
}

// serverSettings are the server-wide values the gate reads on every decision.
type serverSettings struct {
	SiteURL  string
	SiteName string
	// IsMFAEnabled is EnableMultifactorAuthentication: only then has the server checked a TOTP code.
	IsMFAEnabled bool
}

// attempt is where a sign-in came from, as the server saw it.
type attempt struct {
	IP        string
	UserAgent string
}

// emailKind is one of the two emails, each rate limited on its own KV key so a reminder
// sent just before the cutoff does not suppress the refusal explanation just after it.
type emailKind struct {
	keyPrefix string
	name      string
}

var (
	reminderEmail = emailKind{keyPrefix: "reminded_", name: "reminder"}
	refusalEmail  = emailKind{keyPrefix: "refusalmailed_", name: "refusal"}
)

// emailInterval is the minimum gap between two emails of one kind to one user.
const emailInterval = 24 * time.Hour

// rejectionReason is what UserWillLogIn returns. Password logins mask it as "invalid credentials".
const rejectionReason = "this sign-in needs TOTP multi-factor authentication"

// gate decides each login and sends the emails.
type gate struct {
	deps deps
	cfg  func() *configuration
	now  func() time.Time
}

// check is the UserWillLogIn decision: "" allows the login, anything else rejects it.
func (g *gate) check(user *model.User, at attempt) string {
	cfg := g.cfg()
	logArgs := []any{"username", user.Username, "ip", at.IP, "user_agent", at.UserAgent}

	switch {
	case user.IsBot:
		g.deps.logInfo("Login allowed: bot", logArgs...)
		return ""
	case user.MfaActive && g.deps.server().IsMFAEnabled:
		g.deps.logInfo("Login allowed: TOTP checked by the server", logArgs...)
		return ""
	case cfg.isExempt(user.Username):
		g.deps.logInfo("Login allowed: exempt username", logArgs...)
		return ""
	}

	now := g.now()
	if now.Before(cfg.totpRequiredFrom) {
		isSent, err := g.sendOnce(cfg, reminderEmail, user, at, now)
		g.logEmailResult("Login allowed without TOTP before the cutoff", logArgs, reminderEmail, isSent, err)
		return ""
	}
	isSent, err := g.sendOnce(cfg, refusalEmail, user, at, now)
	g.logEmailResult("Login rejected: TOTP required", logArgs, refusalEmail, isSent, err)
	return rejectionReason
}

// logEmailResult logs a decision together with what happened to its email.
func (g *gate) logEmailResult(decision string, logArgs []any, kind emailKind, isSent bool, err error) {
	switch {
	case err != nil:
		g.deps.logError(decision+", "+kind.name+" email failed", append(logArgs, "error", err.Error())...)
	case !isSent:
		g.deps.logInfo(decision+", "+kind.name+" email already sent in the last 24 hours", logArgs...)
	default:
		g.deps.logInfo(decision+", "+kind.name+" email sent", logArgs...)
	}
}

// sendOnce emails the user unless an email of this kind went to them in the last 24 hours.
// The atomic set-if-absent makes concurrent logins send at most one email.
func (g *gate) sendOnce(cfg *configuration, kind emailKind, user *model.User, at attempt, now time.Time) (bool, error) {
	rateKey := kind.keyPrefix + user.Id
	isFirst, err := g.deps.kvSetIfAbsent(rateKey, []byte(now.UTC().Format(time.RFC3339)), emailInterval)
	if err != nil || !isFirst {
		return false, err
	}
	server := g.deps.server()
	zone := user.GetPreferredTimezone()
	subject, body, err := renderEmail(kind, emailData{
		SiteName:  server.SiteName,
		SiteURL:   server.SiteURL,
		Username:  user.Username,
		Cutoff:    formatInZone(cfg.totpRequiredFrom, zone),
		IP:        at.IP,
		UserAgent: at.UserAgent,
		Time:      formatInZone(now, zone),
	})
	if err == nil {
		err = g.deps.sendMail(user.Email, subject, body)
	}
	if err != nil {
		// Clearing the rate limit lets the user's next login retry the email.
		return false, errors.Join(err, g.deps.kvDelete(rateKey))
	}
	return true, nil
}

// formatInZone shows a time in the named IANA timezone, or UTC when it is empty or unknown.
func formatInZone(t time.Time, name string) string {
	loc := time.UTC
	if name != "" {
		if l, err := time.LoadLocation(name); err == nil {
			loc = l
		}
	}
	return t.In(loc).Format("Mon 2 Jan 2006, 15:04 MST")
}
