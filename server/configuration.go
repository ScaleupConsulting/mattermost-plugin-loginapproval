package main

import (
	"reflect"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// configuration holds the System Console settings. Public fields are loaded from the server
// configuration in OnConfigurationChange; exemptUsernames is derived from ExemptUsernames there.
// A configuration is never modified after setConfiguration, so readers share one pointer.
type configuration struct {
	ApprovalWindowMinutes int
	EmailRateLimitMinutes int
	ExemptUsernames       string

	exemptUsernames map[string]bool
}

// validate rejects settings that would make every link expire at once or disable the rate limit.
func (c *configuration) validate() error {
	if c.ApprovalWindowMinutes < 1 {
		return errors.Errorf("ApprovalWindowMinutes must be at least 1, got %d", c.ApprovalWindowMinutes)
	}
	if c.EmailRateLimitMinutes < 1 {
		return errors.Errorf("EmailRateLimitMinutes must be at least 1, got %d", c.EmailRateLimitMinutes)
	}
	return nil
}

// parseExemptUsernames turns the comma-separated setting into a lowercase lookup set.
func parseExemptUsernames(list string) map[string]bool {
	set := map[string]bool{}
	for name := range strings.SplitSeq(list, ",") {
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
			set[name] = true
		}
	}
	return set
}

// approvalWindow is both the emailed link's lifetime and how long an approval waits to be used.
func (c *configuration) approvalWindow() time.Duration {
	return time.Duration(c.ApprovalWindowMinutes) * time.Minute
}

// emailRateLimit is the minimum gap between two approval emails to one user.
func (c *configuration) emailRateLimit() time.Duration {
	return time.Duration(c.EmailRateLimitMinutes) * time.Minute
}

// isExempt reports whether the admin listed this username as password-only.
func (c *configuration) isExempt(username string) bool {
	return c.exemptUsernames[strings.ToLower(username)]
}

// getConfiguration returns the active configuration under lock.
func (p *Plugin) getConfiguration() *configuration {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()

	if p.configuration == nil {
		return &configuration{}
	}
	return p.configuration
}

// setConfiguration replaces the active configuration under lock. It panics when handed the
// active pointer itself, which would mean a caller mutated it instead of building a new one.
func (p *Plugin) setConfiguration(configuration *configuration) {
	p.configurationLock.Lock()
	defer p.configurationLock.Unlock()

	if configuration != nil && p.configuration == configuration {
		if reflect.ValueOf(*configuration).NumField() == 0 {
			return
		}
		panic("setConfiguration called with the existing configuration")
	}
	p.configuration = configuration
}

// OnConfigurationChange loads and validates the settings, keeping the previous ones on error.
func (p *Plugin) OnConfigurationChange() error {
	configuration := new(configuration)
	if err := p.API.LoadPluginConfiguration(configuration); err != nil {
		return errors.Wrap(err, "failed to load plugin configuration")
	}
	if err := configuration.validate(); err != nil {
		return err
	}
	configuration.exemptUsernames = parseExemptUsernames(configuration.ExemptUsernames)
	p.setConfiguration(configuration)
	return nil
}
