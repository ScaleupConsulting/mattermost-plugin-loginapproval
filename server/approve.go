package main

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/mattermost/mattermost/server/public/plugin"
)

// csrfCookie holds the double-submit value the confirmation page also puts in its form. A mail
// scanner that only fetches the link never posts the form, so it cannot approve.
const csrfCookie = "loginapproval_csrf"

// ServeHTTP serves the unauthenticated approval page: GET shows the request, POST approves it.
func (p *Plugin) ServeHTTP(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/approve" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		p.handleConfirm(w, r)
	case http.MethodPost:
		p.handleApprove(c, w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleConfirm shows who asked to sign in, from where, with an Approve button. It changes nothing.
func (p *Plugin) handleConfirm(w http.ResponseWriter, r *http.Request) {
	cfg := p.getConfiguration()
	token := r.URL.Query().Get("token")
	pending, _, err := p.gate.lookupPending(cfg, token)
	if err != nil {
		p.renderLookupError(w, err)
		return
	}
	csrf := make([]byte, 32)
	if _, err := p.gate.random(csrf); err != nil {
		p.gate.deps.logError("Could not generate CSRF value", "error", err.Error())
		p.renderMessage(w, http.StatusInternalServerError, "Something went wrong", "Open the link from your email again.")
		return
	}
	csrfValue := base64.RawURLEncoding.EncodeToString(csrf)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookie,
		Value:    csrfValue,
		Path:     "/plugins/" + manifest.Id + "/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(p.gate.deps.server().SiteURL, "https://"),
		SameSite: http.SameSiteStrictMode,
	})
	p.render(w, http.StatusOK, page{
		Title:   "Approve this sign-in?",
		Pending: pending,
		Time:    formatInZone(pending.RequestedAt, pending.Timezone),
		Token:   token,
		CSRF:    csrfValue,
	})
}

// handleApprove spends the token after checking the form came from the confirmation page.
func (p *Plugin) handleApprove(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		p.renderMessage(w, http.StatusBadRequest, "Could not read the form", "Open the link from your email again.")
		return
	}
	cookie, err := r.Cookie(csrfCookie)
	formCSRF := r.PostForm.Get("csrf")
	if err != nil || formCSRF == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(formCSRF)) != 1 {
		p.gate.deps.logInfo("Approval rejected: missing or mismatched CSRF value", "approver_ip", c.IPAddress)
		p.renderMessage(w, http.StatusForbidden, "Approval not accepted", "Open the link from your email again and press Approve on that page.")
		return
	}

	pending, err := p.gate.approve(r.PostForm.Get("token"), c.IPAddress)
	if err != nil {
		p.renderLookupError(w, err)
		return
	}
	p.renderMessage(w, http.StatusOK, "Sign-in approved",
		"Now sign in again as "+pending.Username+" on the same device and network within "+
			formatMinutes(p.getConfiguration().ApprovalWindowMinutes)+". The approval works once.")
}

// renderLookupError turns a token lookup failure into a page the user can act on.
func (p *Plugin) renderLookupError(w http.ResponseWriter, err error) {
	if errors.Is(err, errTokenGone) {
		p.renderMessage(w, http.StatusGone, "Link expired or already used",
			"Sign in again to get a new email, or turn on multi-factor authentication in Profile > Security to skip emails.")
		return
	}
	p.gate.deps.logError("Approval lookup failed", "error", err.Error())
	p.renderMessage(w, http.StatusInternalServerError, "Something went wrong", "Try the link again in a minute.")
}

// renderMessage shows a page with a title and one paragraph.
func (p *Plugin) renderMessage(w http.ResponseWriter, status int, title, message string) {
	p.render(w, status, page{Title: title, Message: message})
}

// render writes a page with headers that keep the token out of caches, referrers and frames.
func (p *Plugin) render(w http.ResponseWriter, status int, data page) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	w.WriteHeader(status)
	if err := pageTemplate.Execute(w, data); err != nil {
		p.gate.deps.logError("Could not render approval page", "error", err.Error())
	}
}

// formatMinutes renders a minute count for page text.
func formatMinutes(n int) string {
	if n == 1 {
		return "1 minute"
	}
	return strconv.Itoa(n) + " minutes"
}
