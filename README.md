# Login Approval (com.scaleupconsulting.loginapproval)

Requires TOTP multi-factor authentication on Mattermost Team Edition, which cannot enforce it, after a grace period. Requires Mattermost 12.0+.

- Users with TOTP turned on sign in as usual: the server checks the code before this plugin runs.
- Before the cutoff, everyone else signs in with a password and gets a reminder email, at most once a day, with the cutoff in their own timezone (UTC when they have none) and the steps to turn TOTP on.
- From the cutoff, their sign-ins are refused. Mattermost shows that as "invalid email or password", so they also get an email, at most once a day, explaining it and how to recover.
- Bots, personal access tokens and the usernames listed in the settings skip the check and get no emails.
- Settings: `TOTP required from`, an RFC 3339 UTC timestamp such as `2026-11-28T22:00:00Z` (09:00 on 29 November 2026 in Sydney), and exempt usernames. The plugin refuses to start without a valid cutoff, without Enable Multi-factor Authentication, without a Site URL or without email notifications.

TOTP can be turned on only in the web app or the desktop app, under Profile > Security > Multi-factor Authentication. The mobile app asks for the code at sign-in but cannot turn TOTP on. A user locked out after the cutoff with no other signed-in session needs an admin to add them to the exempt usernames while they set it up.

The check runs in the `UserWillLogIn` hook, which fails open: while the plugin is disabled or not running, logins are not checked.

Build with `build/docker-build.sh` (needs only Docker), or `make -j1 server && make -j1 bundle` with Go installed, then upload `dist/com.scaleupconsulting.loginapproval-<version>.tar.gz` in System Console > Plugins > Plugin Management. Unit tests: `cd server && go test ./...`.
