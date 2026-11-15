package main

import (
	"reflect"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// configuration holds the System Console settings. Public fields are loaded from the server
// configuration; the private fields are derived from them by loadConfiguration.
// A configuration is never modified after setConfiguration, so readers share one pointer.
type configuration struct {
	TOTPRequiredFrom string
	ExemptUsernames  string

	totpRequiredFrom time.Time
	exemptUsernames  map[string]bool
}

// parseTOTPRequiredFrom accepts only an RFC 3339 timestamp in UTC, so the setting reads the same to every admin.
func parseTOTPRequiredFrom(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, errors.New("set TOTP required from (TOTPRequiredFrom) to an RFC 3339 UTC timestamp such as 2026-11-28T22:00:00Z")
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, errors.Wrapf(err, "TOTPRequiredFrom %q is not an RFC 3339 timestamp", value)
	}
	if _, offset := t.Zone(); offset != 0 {
		return time.Time{}, errors.Errorf("TOTPRequiredFrom %q must be in UTC, ending in Z", value)
	}
	return t.UTC(), nil
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

// loadConfiguration reads and parses the settings and makes them active, or changes nothing on error.
func (p *Plugin) loadConfiguration() error {
	configuration := new(configuration)
	if err := p.API.LoadPluginConfiguration(configuration); err != nil {
		return errors.Wrap(err, "failed to load plugin configuration")
	}
	cutoff, err := parseTOTPRequiredFrom(configuration.TOTPRequiredFrom)
	if err != nil {
		return err
	}
	configuration.totpRequiredFrom = cutoff
	configuration.exemptUsernames = parseExemptUsernames(configuration.ExemptUsernames)
	p.setConfiguration(configuration)
	return nil
}

// OnConfigurationChange keeps the previous settings when the new ones are invalid.
func (p *Plugin) OnConfigurationChange() error {
	return p.loadConfiguration()
}
