package main

import (
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // the plugin binary runs wherever the server does, which may lack zoneinfo

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

// Plugin gates every login on TOTP or an emailed approval.
type Plugin struct {
	plugin.MattermostPlugin

	configurationLock sync.RWMutex
	configuration     *configuration

	gate *gate
}

// OnActivate refuses to start when approval emails could not be sent or linked.
func (p *Plugin) OnActivate() error {
	d := apiDeps{api: p.API}
	if d.server().SiteURL == "" {
		return errors.New("set System Console > Environment > Web Server > Site URL: approval emails link to it")
	}
	if err := d.checkMailEnabled(); err != nil {
		return err
	}
	p.gate = &gate{deps: d, cfg: p.getConfiguration, now: time.Now, random: rand.Read}
	return nil
}

// UserWillLogIn allows bots, TOTP users, exempt users and approved sign-ins, and emails everyone else.
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

func (d apiDeps) kvGet(key string) ([]byte, error) {
	value, appErr := d.api.KVGet(key)
	return value, asError(appErr)
}

func (d apiDeps) kvSet(key string, value []byte, ttl time.Duration) error {
	_, appErr := d.api.KVSetWithOptions(key, value, model.PluginKVSetOptions{ExpireInSeconds: int64(ttl.Seconds())})
	return asError(appErr)
}

func (d apiDeps) kvSetIfAbsent(key string, value []byte, ttl time.Duration) (bool, error) {
	// Atomic with a nil OldValue inserts only when the key is absent; the store first drops an expired row.
	isSet, appErr := d.api.KVSetWithOptions(key, value, model.PluginKVSetOptions{
		Atomic: true, OldValue: nil, ExpireInSeconds: int64(ttl.Seconds()),
	})
	return isSet, asError(appErr)
}

func (d apiDeps) kvCompareAndDelete(key string, oldValue []byte) (bool, error) {
	isDeleted, appErr := d.api.KVCompareAndDelete(key, oldValue)
	return isDeleted, asError(appErr)
}

func (d apiDeps) kvDelete(key string) error {
	return asError(d.api.KVDelete(key))
}

// checkMailEnabled fails when SendMail would silently drop mail: the server skips it unless
// email notifications are on.
func (d apiDeps) checkMailEnabled() error {
	if cfg := d.api.GetConfig(); cfg.EmailSettings.SendEmailNotifications == nil || !*cfg.EmailSettings.SendEmailNotifications {
		return errors.New("turn on System Console > Site Configuration > Notifications > Enable Email Notifications: approval emails are dropped without it")
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
