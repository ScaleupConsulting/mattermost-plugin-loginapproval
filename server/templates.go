package main

import (
	"bytes"
	"html/template"
)

// approvalEmail is the data shown in the approval email.
type approvalEmail struct {
	SiteName  string
	Username  string
	IP        string
	UserAgent string
	Time      string
	Link      string
	Window    string
}

// The server reports a rejected password login as "invalid credentials", so the email explains it.
var emailTemplate = template.Must(template.New("email").Parse(`<!DOCTYPE html>
<html><body style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.5;color:#1f2328">
<p>Someone (hopefully you) just tried to sign in to {{.SiteName}} as <b>{{.Username}}</b>.</p>
<table style="border-collapse:collapse;margin:8px 0 16px">
<tr><td style="padding:2px 12px 2px 0;color:#57606a">IP address</td><td>{{.IP}}</td></tr>
<tr><td style="padding:2px 12px 2px 0;color:#57606a">Device</td><td>{{.UserAgent}}</td></tr>
<tr><td style="padding:2px 12px 2px 0;color:#57606a">Time</td><td>{{.Time}}</td></tr>
</table>
<p>Mattermost said the email, username or password was invalid. That is expected: this sign-in is waiting for your approval.</p>
<p><b>If this was you:</b> open the link, press Approve, then sign in again on the same device and network within {{.Window}}.</p>
<p><a href="{{.Link}}" style="display:inline-block;padding:10px 18px;background:#1c58d9;color:#ffffff;text-decoration:none;border-radius:4px">Review this sign-in</a></p>
<p style="color:#57606a">The link works once and expires in {{.Window}}.</p>
<p><b>If this was not you:</b> ignore this email and nobody gets in. Someone may know your password, so change it.</p>
<p><b>To stop these emails:</b> turn on multi-factor authentication in Profile &gt; Security. A sign-in with an authenticator code needs no email.</p>
</body></html>`))

// renderApprovalEmail returns the subject and HTML body of an approval email.
func renderApprovalEmail(e approvalEmail) (string, string, error) {
	var body bytes.Buffer
	if err := emailTemplate.Execute(&body, e); err != nil {
		return "", "", err
	}
	return "Approve your sign-in to " + e.SiteName, body.String(), nil
}

// page is the data for every approval web page.
type page struct {
	Title   string
	Message string
	// Pending and CSRF are set only on the confirmation page, which shows the Approve form.
	Pending *pendingApproval
	Time    string
	Token   string
	CSRF    string
}

var pageTemplate = template.Must(template.New("page").Parse(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{.Title}}</title>
<style>
body{margin:0;padding:16px;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:16px;line-height:1.5;background:#f6f8fa;color:#1f2328}
main{max-width:480px;margin:24px auto;background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:20px}
h1{font-size:20px;margin:0 0 12px}
dl{margin:0 0 16px}dt{color:#57606a;font-size:14px}dd{margin:0 0 8px;overflow-wrap:anywhere}
button{width:100%;padding:14px;font-size:17px;border:0;border-radius:6px;background:#1c58d9;color:#fff}
@media (prefers-color-scheme:dark){body{background:#0d1117;color:#e6edf3}main{background:#161b22;border-color:#30363d}dt{color:#8b949e}}
</style></head><body><main>
<h1>{{.Title}}</h1>
{{if .Pending}}
<p>Approve only if you just tried to sign in as <b>{{.Pending.Username}}</b> from this device and place.</p>
<dl>
<dt>IP address</dt><dd>{{.Pending.IP}}</dd>
<dt>Device</dt><dd>{{.Pending.UserAgent}}</dd>
<dt>Time</dt><dd>{{.Time}}</dd>
</dl>
<form method="post" action="approve">
<input type="hidden" name="token" value="{{.Token}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<button type="submit">Approve</button>
</form>
<p>Not you? Close this page and change your password.</p>
{{else}}
<p>{{.Message}}</p>
{{end}}
</main></body></html>`))
