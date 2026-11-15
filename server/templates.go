package main

import (
	"bytes"
	"fmt"
	"html/template"
)

// emailData is what both emails show. Times are already formatted in the user's timezone.
type emailData struct {
	SiteName  string
	SiteURL   string
	Username  string
	Cutoff    string
	IP        string
	UserAgent string
	Time      string
}

// The setup steps follow the Mattermost 12.0 webapp. The mobile app can enter a code at sign-in
// but has no screen that turns TOTP on, so the steps point at a browser or the desktop app.
var emailTemplates = template.Must(template.New("").Parse(`
{{define "style"}}font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.5;color:#1f2328{{end}}

{{define "steps"}}
<ol>
<li>Install an authenticator app on your phone, such as Google Authenticator, Microsoft Authenticator or 1Password.</li>
<li>{{.}}</li>
<li>Select your profile picture at the top right, then <b>Profile</b>.</li>
<li>Select <b>Security</b>, then <b>Edit</b> next to <b>Multi-factor Authentication</b>, then <b>Add MFA to Account</b>.</li>
<li>Scan the QR code with the authenticator app, or type the secret shown under it into the app.</li>
<li>Enter the 6-digit code the app shows and select <b>Save</b>, then <b>Okay</b>.</li>
</ol>
<p>From then on every sign-in asks for a code from the app, in the browser, the desktop app and the mobile app. The Mattermost mobile app accepts these codes but cannot turn multi-factor authentication on, so use a browser or the desktop app for the steps above.</p>
{{end}}

{{define "reminder"}}<!DOCTYPE html>
<html><body style="{{template "style"}}">
<p>Hi {{.Username}},</p>
<p>From <b>{{.Cutoff}}</b>, signing in to {{.SiteName}} will need a code from an authenticator app (TOTP multi-factor authentication). Your account does not have it turned on yet, so after that time you will not be able to sign in.</p>
<p>To turn it on:</p>
{{template "steps" (printf "Sign in to %s in a web browser on a computer, or in the Mattermost desktop app." .SiteURL)}}
<p style="color:#57606a">You get this reminder at most once a day while you sign in without multi-factor authentication. This one was triggered by a sign-in from {{.IP}} ({{.UserAgent}}) at {{.Time}}.</p>
</body></html>{{end}}

{{define "refusal"}}<!DOCTYPE html>
<html><body style="{{template "style"}}">
<p>Someone (hopefully you) just tried to sign in to {{.SiteName}} as <b>{{.Username}}</b>.</p>
<table style="border-collapse:collapse;margin:8px 0 16px">
<tr><td style="padding:2px 12px 2px 0;color:#57606a">IP address</td><td>{{.IP}}</td></tr>
<tr><td style="padding:2px 12px 2px 0;color:#57606a">Device</td><td>{{.UserAgent}}</td></tr>
<tr><td style="padding:2px 12px 2px 0;color:#57606a">Time</td><td>{{.Time}}</td></tr>
</table>
<p>Since <b>{{.Cutoff}}</b>, signing in to {{.SiteName}} needs a code from an authenticator app (TOTP multi-factor authentication). Your account does not have it turned on, so the sign-in was refused.</p>
<p>Mattermost said the email, username or password was invalid. Your password was in fact correct: this email goes out only after it is checked, and Mattermost shows that message for any refused sign-in.</p>
<p><b>If you are still signed in somewhere</b> in a web browser or the Mattermost desktop app, turn multi-factor authentication on there:</p>
{{template "steps" (printf "Go to %s in that web browser or desktop app, where you are still signed in." .SiteURL)}}
<p><b>If you are not signed in anywhere else</b>, ask a system admin to add your username to the plugin's exempt list for a short time. Sign in, follow the steps above, then ask them to remove you again.</p>
<p><b>If this was not you:</b> nobody got in, but someone knows your password. Change it as soon as you are signed in again.</p>
<p style="color:#57606a">You get this email at most once a day.</p>
</body></html>{{end}}
`))

// renderEmail returns the subject and HTML body of one kind of email.
func renderEmail(kind emailKind, e emailData) (string, string, error) {
	var body bytes.Buffer
	if err := emailTemplates.ExecuteTemplate(&body, kind.name, e); err != nil {
		return "", "", err
	}
	switch kind {
	case reminderEmail:
		return "Turn on multi-factor authentication for " + e.SiteName + " before " + e.Cutoff, body.String(), nil
	case refusalEmail:
		return "Your sign-in to " + e.SiteName + " needs multi-factor authentication", body.String(), nil
	}
	return "", "", fmt.Errorf("unknown email kind %q", kind.name)
}
