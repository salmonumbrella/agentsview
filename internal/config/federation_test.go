package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFederationConfigDefaultsAndValidation(t *testing.T) {
	cfg := loadMinimalWithConfig(t, map[string]any{"federation": map[string]any{"role": "hub"}})
	assert.Equal(t, "hub", cfg.Federation.Role)
	assert.Equal(t, "member-controlled", cfg.Federation.Hub.Retention)
	assert.Equal(t, []string{"summary"}, cfg.Federation.Hub.AllowedLevels)
	assert.Equal(t, 3, cfg.Federation.Hub.MinGroupSize)
	assert.Equal(t, "none", cfg.Federation.Hub.Processing)
}

func TestFederationHubPolicyOnlyValidatedForHub(t *testing.T) {
	for _, role := range []string{"off", "spoke", "hub", "unknown"} {
		cfg := map[string]any{"federation": map[string]any{"role": role, "hub": map[string]any{"retention": "", "allowed_levels": []string{"x"}}}}
		err := loadMinimalErrWithConfig(t, cfg)
		if role == "off" || role == "spoke" {
			assert.NoError(t, err)
		} else if role == "unknown" {
			assert.ErrorContains(t, err, "[federation] role must be off, spoke or hub")
		} else {
			assert.Error(t, err)
		}
	}
}

func TestFederationHubDisablesDiscovery(t *testing.T) {
	for _, tc := range []struct {
		role string
		want bool
	}{{"hub", true}, {"spoke", false}, {"off", false}} {
		t.Run(tc.role, func(t *testing.T) {
			cfg := loadMinimalWithConfig(t, map[string]any{"federation": map[string]any{"role": tc.role}})
			assert.Equal(t, tc.want, cfg.NoSync)
		})
	}
}
