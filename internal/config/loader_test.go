package config_test

import (
	"testing"

	"github.com/thiagohdeplima/riskctl/internal/config"
)

func TestLoad_NoEnvVars(t *testing.T) {
	t.Setenv("RISKCTL_SOURCES_AWS_REGION", "")

	loader := &config.ConfigLoader{}
	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Sources.AWS != nil && cfg.Sources.AWS.Region != "" {
		t.Errorf("expected empty region, got %q", cfg.Sources.AWS.Region)
	}
}

func TestLoad_AWSRegionFromEnv(t *testing.T) {
	t.Setenv("RISKCTL_SOURCES_AWS_REGION", "us-west-2")

	loader := &config.ConfigLoader{}
	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Sources.AWS == nil {
		t.Fatal("expected Sources.AWS to be non-nil")
	}
	if cfg.Sources.AWS.Region != "us-west-2" {
		t.Errorf("expected Region us-west-2, got %q", cfg.Sources.AWS.Region)
	}
}
