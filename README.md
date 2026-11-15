# Login Approval (com.scaleupconsulting.loginapproval)

A second factor for Mattermost Team Edition, which cannot enforce TOTP. Requires Mattermost 12.0+.

- Users with TOTP turned on (Profile > Security) sign in as usual: the server checks the code before this plugin runs.
- Everyone else gets their first sign-in rejected and an email with a link. Opening the link shows the IP address, device and time; pressing Approve allows one sign-in from that same IP address and user agent within the approval window.
- Mattermost shows the rejected sign-in as "invalid credentials", so the email explains that.
- Bots, personal access tokens and the usernames listed in the settings skip the check.
- Settings: approval window (default 15 minutes), email rate limit (default one email per user per 2 minutes) and exempt usernames.

The check runs in the `UserWillLogIn` hook, which fails open: while the plugin is disabled or not running, logins are not checked.

Build with `build/docker-build.sh` (needs only Docker), or `make -j1 server && make -j1 bundle` with Go installed, then upload `dist/com.scaleupconsulting.loginapproval-<version>.tar.gz` in System Console > Plugins > Plugin Management. Unit tests: `cd server && go test ./...`.
