package main

import (
	"errors"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // the plugin binary runs wherever the server does, which may lack zoneinfo

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

// Plugin requires TOTP for every login after a configured cutoff and emails users without it.
type Plugin struct {
	plugin.MattermostPlugin

	configurationLock sync.RWMutex
	configuration     *configuration

	gate *gate
}

// OnActivate refuses to start without a valid cutoff, server MFA, a Site URL or working email.
// The server only logs an OnConfigurationChange error at activation, so the settings are checked here.
func (p *Plugin) OnActivate() error {
	if err := p.loadConfiguration(); err != nil {
		return err
	}
	d := apiDeps{api: p.API}
	server := d.server()
	if server.SiteURL == "" {
		return errors.New("set System Console > Environment > Web Server > Site URL: the emails link to it")
	}
	if !server.IsMFAEnabled {
		return errors.New("turn on System Console > Authentication > MFA > Enable Multi-factor Authentication: users cannot set up TOTP without it")
	}
	if err := d.checkMailEnabled(); err != nil {
		return err
	}
	p.gate = &gate{deps: d, cfg: p.getConfiguration, now: time.Now}
	return nil
}

// UserWillLogIn allows bots, TOTP users and exempt users, and handles everyone else per the cutoff.
func (p *Plugin) UserWillLogIn(c *plugin.Context, user *model.User) string {
	return p.gate.check(user, attempt{IP: c.IPAddress, UserAgent: c.UserAgent})
}

// apiDeps implements deps on the real plugin API.
type apiDeps struct {
	api plugin.API
}

// asError keeps a nil *model.AppError from becoming a non-nil error interface.
func asError(appErr *model.AppError) error {
	if appErr == nil {
		return nil
	}
	return appErr
}

func (d apiDeps) kvSetIfAbsent(key string, value []byte, ttl time.Duration) (bool, error) {
	// Atomic with a nil OldValue inserts only when the key is absent; the store first drops an expired row.
	isSet, appErr := d.api.KVSetWithOptions(key, value, model.PluginKVSetOptions{
		Atomic: true, OldValue: nil, ExpireInSeconds: int64(ttl.Seconds()),
	})
	return isSet, asError(appErr)
}

func (d apiDeps) kvDelete(key string) error {
	return asError(d.api.KVDelete(key))
}

// checkMailEnabled fails when SendMail would silently drop mail: the server skips it unless
// email notifications are on.
func (d apiDeps) checkMailEnabled() error {
	if cfg := d.api.GetConfig(); cfg.EmailSettings.SendEmailNotifications == nil || !*cfg.EmailSettings.SendEmailNotifications {
		return errors.New("turn on System Console > Site Configuration > Notifications > Enable Email Notifications: the plugin's emails are dropped without it")
	}
	return nil
}

func (d apiDeps) sendMail(to, subject, htmlBody string) error {
	if err := d.checkMailEnabled(); err != nil {
		return err
	}
	return asError(d.api.SendMail(to, subject, htmlBody))
}

func (d apiDeps) server() serverSettings {
	cfg := d.api.GetConfig()
	return serverSettings{
		SiteURL:      strings.TrimRight(model.SafeDereference(cfg.ServiceSettings.SiteURL), "/"),
		SiteName:     model.SafeDereference(cfg.TeamSettings.SiteName),
		IsMFAEnabled: model.SafeDereference(cfg.ServiceSettings.EnableMultifactorAuthentication),
	}
}

func (d apiDeps) logInfo(msg string, keyValuePairs ...any) {
	d.api.LogInfo(msg, keyValuePairs...)
}

func (d apiDeps) logError(msg string, keyValuePairs ...any) {
	d.api.LogError(msg, keyValuePairs...)
}
