package renderer_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/thiagohdeplima/riskctl/internal/findings"
	"github.com/thiagohdeplima/riskctl/internal/renderer"
)

type envelope struct {
	GeneratedAt string             `json:"generated_at"`
	Count       int                `json:"count"`
	Findings    []findings.Finding `json:"findings"`
}

func TestJSONRenderer_OneFinding(t *testing.T) {
	now := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	input := []findings.Finding{
		{
			FindingID:    "arn:aws:inspector2:us-east-1:123456789012:finding/abc",
			Source:       "aws_inspector",
			Severity:     "HIGH",
			VulnID:       "CVE-2024-1234",
			FixAvailable: true,
			AssetType:    "AWS_EC2_INSTANCE",
			AssetID:      "i-0123456789abcdef0",
			FirstSeen:    now,
			LastSeen:     now,
		},
	}

	var buf bytes.Buffer
	r := &renderer.JSONRenderer{}
	if err := r.Render(context.Background(), input, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var env envelope
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if _, err := time.Parse(time.RFC3339, env.GeneratedAt); err != nil {
		t.Errorf("generated_at is not valid RFC3339: %v", err)
	}
	if env.Count != 1 {
		t.Errorf("expected count 1, got %d", env.Count)
	}
	if len(env.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(env.Findings))
	}
	if env.Findings[0].FindingID != input[0].FindingID {
		t.Errorf("expected FindingID %q, got %q", input[0].FindingID, env.Findings[0].FindingID)
	}
}

func TestJSONRenderer_EmptySlice(t *testing.T) {
	var buf bytes.Buffer
	r := &renderer.JSONRenderer{}
	if err := r.Render(context.Background(), []findings.Finding{}, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var env envelope
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if env.Count != 0 {
		t.Errorf("expected count 0, got %d", env.Count)
	}
	if len(env.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(env.Findings))
	}
}

func TestJSONRenderer_NilSlice(t *testing.T) {
	var buf bytes.Buffer
	r := &renderer.JSONRenderer{}
	if err := r.Render(context.Background(), nil, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var env envelope
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if env.Count != 0 {
		t.Errorf("expected count 0, got %d", env.Count)
	}
	if env.Findings == nil {
		t.Error("expected findings to be empty array, got null")
	}
}
