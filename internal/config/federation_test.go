package config

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestFederationConfigDefaultsAndValidation(t *testing.T) {
	cfg := loadMinimalWithConfig(t, map[string]any{"federation": map[string]any{"role": "hub"}})
	assert.Equal(t, "hub", cfg.Federation.Role)
	assert.Equal(t, "member-controlled", cfg.Federation.Hub.Retention)
	assert.Equal(t, []string{"summary"}, cfg.Federation.Hub.AllowedLevels)
	assert.Equal(t, 3, cfg.Federation.Hub.MinGroupSize)
	assert.Equal(t, "none", cfg.Federation.Hub.Processing)
	err := loadMinimalErrWithConfig(t, map[string]any{"federation": map[string]any{"role": "unknown"}})
	require.Error(t, err)
}

func TestFederationHubPolicyOnlyValidatedForHub(t *testing.T) {
	for _, role := range []string{"off", "spoke", "hub", "unknown"} {
		cfg := map[string]any{"federation": map[string]any{"role": role, "hub": map[string]any{"retention": "", "allowed_levels": []string{"x"}}}}
		err := loadMinimalErrWithConfig(t, cfg)
		if role == "off" || role == "spoke" {
			assert.NoError(t, err)
		} else {
			assert.Error(t, err)
		}
	}
}
