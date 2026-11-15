package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
)

// deps is everything the gate needs from the server, so tests can run it without one.
type deps interface {
	kvGet(key string) ([]byte, error)
	kvSet(key string, value []byte, ttl time.Duration) error
	kvSetIfAbsent(key string, value []byte, ttl time.Duration) (bool, error)
	kvCompareAndDelete(key string, oldValue []byte) (bool, error)
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

// KV key prefixes. Tokens appear only as SHA-256 hashes; the raw token exists only in the email.
const (
	keyPendingPrefix   = "pending_"   // + hex(sha256(token)): an emailed, not yet approved request
	keyApprovedPrefix  = "approved_"  // + userID + "_" + hex(sha256(ip, ua)): one usable approval
	keyEmailSentPrefix = "emailsent_" // + userID: present while the email rate limit holds
)

// rejectionReason is what UserWillLogIn returns. Password logins mask it as "invalid credentials".
const rejectionReason = "this sign-in needs approval from the link emailed to you"

// tokenBytes is the size of the random approval token.
const tokenBytes = 32

// pendingApproval is stored under the token hash between the email and the Approve click.
type pendingApproval struct {
	UserID      string    `json:"user_id"`
	Username    string    `json:"username"`
	IP          string    `json:"ip"`
	UserAgent   string    `json:"user_agent"`
	RequestedAt time.Time `json:"requested_at"`
	// Timezone is the user's Mattermost timezone, so the page shows the time the email showed.
	Timezone string `json:"timezone"`
}

// grantedApproval is stored per user, IP and user agent until a login consumes it.
type grantedApproval struct {
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	ApprovedAt time.Time `json:"approved_at"`
}

// gate decides each login and owns the approval records.
type gate struct {
	deps   deps
	cfg    func() *configuration
	now    func() time.Time
	random func([]byte) (int, error)
}

// hashToken is the KV identity of an emailed token.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// approvedKey binds an approval to one user, IP and user agent. The NUL keeps "a"+"bc" apart from "ab"+"c".
func approvedKey(userID string, at attempt) string {
	sum := sha256.Sum256([]byte(at.IP + "\x00" + at.UserAgent))
	return keyApprovedPrefix + userID + "_" + hex.EncodeToString(sum[:])
}

// check is the UserWillLogIn decision: "" allows the login, anything else rejects it.
func (g *gate) check(user *model.User, at attempt) string {
	cfg := g.cfg()
	logArgs := []any{"username", user.Username, "ip", at.IP, "user_agent", at.UserAgent}

	switch {
	case user.IsBot:
		return ""
	case user.MfaActive && g.deps.server().IsMFAEnabled:
		return ""
	case cfg.isExempt(user.Username):
		return ""
	}

	isConsumed, err := g.consumeApproval(cfg, user.Id, at)
	if err != nil {
		g.deps.logError("Login rejected: could not read approvals", append(logArgs, "error", err.Error())...)
		return rejectionReason
	}
	if isConsumed {
		g.deps.logInfo("Login allowed by emailed approval", logArgs...)
		return ""
	}

	isSent, err := g.requestApproval(cfg, user, at)
	switch {
	case err != nil:
		g.deps.logError("Login rejected: approval email not sent", append(logArgs, "error", err.Error())...)
	case !isSent:
		g.deps.logInfo("Login rejected: approval email already sent within the rate limit", logArgs...)
	default:
		g.deps.logInfo("Login rejected: approval email sent", logArgs...)
	}
	return rejectionReason
}

// consumeApproval deletes and reports a fresh approval for exactly this user, IP and user agent.
func (g *gate) consumeApproval(cfg *configuration, userID string, at attempt) (bool, error) {
	key := approvedKey(userID, at)
	raw, err := g.deps.kvGet(key)
	if err != nil || raw == nil {
		return false, err
	}
	var granted grantedApproval
	if err := json.Unmarshal(raw, &granted); err != nil {
		return false, fmt.Errorf("decode approval: %w", err)
	}
	if g.now().Sub(granted.ApprovedAt) > cfg.approvalWindow() {
		return false, nil
	}
	// Compare-and-delete makes the approval single-use even when two logins race for it.
	return g.deps.kvCompareAndDelete(key, raw)
}

// requestApproval emails a new approval link unless one went to this user inside the rate limit.
func (g *gate) requestApproval(cfg *configuration, user *model.User, at attempt) (bool, error) {
	now := g.now()
	rateKey := keyEmailSentPrefix + user.Id
	isFirst, err := g.deps.kvSetIfAbsent(rateKey, []byte(now.UTC().Format(time.RFC3339)), cfg.emailRateLimit())
	if err != nil || !isFirst {
		return false, err
	}

	raw := make([]byte, tokenBytes)
	if _, err := g.random(raw); err != nil {
		return false, errors.Join(fmt.Errorf("generate token: %w", err), g.deps.kvDelete(rateKey))
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	pending := pendingApproval{UserID: user.Id, Username: user.Username, IP: at.IP, UserAgent: at.UserAgent, RequestedAt: now, Timezone: user.GetPreferredTimezone()}
	pendingJSON, err := json.Marshal(pending)
	if err != nil {
		return false, errors.Join(err, g.deps.kvDelete(rateKey))
	}
	pendingKey := keyPendingPrefix + hashToken(token)
	if err := g.deps.kvSet(pendingKey, pendingJSON, cfg.approvalWindow()); err != nil {
		return false, errors.Join(fmt.Errorf("store pending approval: %w", err), g.deps.kvDelete(rateKey))
	}

	server := g.deps.server()
	subject, body, err := renderApprovalEmail(approvalEmail{
		SiteName:  server.SiteName,
		Username:  user.Username,
		IP:        at.IP,
		UserAgent: at.UserAgent,
		Time:      formatInZone(now, pending.Timezone),
		Link:      approvalURL(server.SiteURL, token),
		Window:    formatMinutes(cfg.ApprovalWindowMinutes),
	})
	if err == nil {
		err = g.deps.sendMail(user.Email, subject, body)
	}
	if err != nil {
		// Clearing the rate limit lets the user's next attempt retry the email.
		return false, errors.Join(err, g.deps.kvDelete(pendingKey), g.deps.kvDelete(rateKey))
	}
	return true, nil
}

// approvalURL is the confirmation page for one token.
func approvalURL(siteURL, token string) string {
	return siteURL + "/plugins/" + manifest.Id + "/approve?token=" + token
}

// formatInZone shows a time in the named IANA timezone, or UTC when it is empty or unknown.
func formatInZone(t time.Time, name string) string {
	loc := time.UTC
	if name != "" {
		if l, err := time.LoadLocation(name); err == nil {
			loc = l
		}
	}
	return t.In(loc).Format("Mon 2 Jan 2006, 15:04:05 MST")
}

// errTokenGone is returned for an unknown, expired or already used token.
var errTokenGone = errors.New("approval link expired or already used")

// lookupPending returns the request behind a token and its stored bytes, or errTokenGone.
func (g *gate) lookupPending(cfg *configuration, token string) (*pendingApproval, []byte, error) {
	if token == "" {
		return nil, nil, errTokenGone
	}
	raw, err := g.deps.kvGet(keyPendingPrefix + hashToken(token))
	if err != nil {
		return nil, nil, err
	}
	if raw == nil {
		return nil, nil, errTokenGone
	}
	var pending pendingApproval
	if err := json.Unmarshal(raw, &pending); err != nil {
		return nil, nil, fmt.Errorf("decode pending approval: %w", err)
	}
	if g.now().Sub(pending.RequestedAt) > cfg.approvalWindow() {
		return nil, nil, errTokenGone
	}
	return &pending, raw, nil
}

// approve spends a token and grants one login from the IP and user agent that requested it.
func (g *gate) approve(token, approverIP string) (*pendingApproval, error) {
	cfg := g.cfg()
	pending, raw, err := g.lookupPending(cfg, token)
	if err != nil {
		return nil, err
	}
	isDeleted, err := g.deps.kvCompareAndDelete(keyPendingPrefix+hashToken(token), raw)
	if err != nil {
		return nil, err
	}
	if !isDeleted {
		return nil, errTokenGone
	}
	at := attempt{IP: pending.IP, UserAgent: pending.UserAgent}
	grantedJSON, err := json.Marshal(grantedApproval{IP: at.IP, UserAgent: at.UserAgent, ApprovedAt: g.now()})
	if err != nil {
		return nil, err
	}
	if err := g.deps.kvSet(approvedKey(pending.UserID, at), grantedJSON, cfg.approvalWindow()); err != nil {
		return nil, fmt.Errorf("store approval: %w", err)
	}
	g.deps.logInfo("Sign-in approved from emailed link",
		"username", pending.Username, "ip", pending.IP, "user_agent", pending.UserAgent, "approver_ip", approverIP)
	return pending, nil
}
