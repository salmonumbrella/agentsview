package config

import (
	"errors"
	"strings"

	"github.com/BurntSushi/toml"
)

type FederationConfig struct {
	Role string              `json:"-" toml:"role"`
	Hub  FederationHubConfig `json:"-" toml:"hub"`
}

type FederationHubConfig struct {
	Retention         string   `json:"retention" toml:"retention"`
	AllowedLevels     []string `json:"allowed_levels" toml:"allowed_levels"`
	MinGroupSize      int      `json:"min_group_size" toml:"min_group_size"`
	SuggestedProjects []string `json:"suggested_projects" toml:"suggested_projects"`
	Processing        string   `json:"processing" toml:"processing"`
}

func defaultFederationConfig() FederationConfig {
	return FederationConfig{Role: "off", Hub: FederationHubConfig{Retention: "member-controlled", AllowedLevels: []string{"summary"}, MinGroupSize: 3, Processing: "none"}}
}

func (c FederationConfig) Validate() error {
	switch c.Role {
	case "off", "spoke", "hub":
	default:
		return errors.New("[federation] role must be off, spoke or hub")
	}
	if strings.TrimSpace(c.Hub.Retention) == "" || strings.TrimSpace(c.Hub.Processing) == "" || c.Hub.MinGroupSize < 1 || len(c.Hub.AllowedLevels) == 0 {
		return errors.New("[federation.hub] policy fields must be non-empty and min_group_size positive")
	}
	for _, level := range c.Hub.AllowedLevels {
		if level != "summary" && level != "transcript" {
			return errors.New("[federation.hub] allowed_levels must contain summary or transcript")
		}
	}
	return nil
}

func mergeFederationTOML(dst *FederationConfig, src FederationConfig, meta toml.MetaData) {
	if meta.IsDefined("federation", "role") {
		dst.Role = strings.TrimSpace(src.Role)
	}
	if meta.IsDefined("federation", "hub", "retention") {
		dst.Hub.Retention = strings.TrimSpace(src.Hub.Retention)
	}
	if meta.IsDefined("federation", "hub", "allowed_levels") {
		dst.Hub.AllowedLevels = src.Hub.AllowedLevels
	}
	if meta.IsDefined("federation", "hub", "min_group_size") {
		dst.Hub.MinGroupSize = src.Hub.MinGroupSize
	}
	if meta.IsDefined("federation", "hub", "suggested_projects") {
		dst.Hub.SuggestedProjects = src.Hub.SuggestedProjects
	}
	if meta.IsDefined("federation", "hub", "processing") {
		dst.Hub.Processing = strings.TrimSpace(src.Hub.Processing)
	}
}
