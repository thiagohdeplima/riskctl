package renderer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/thiagohdeplima/riskctl/internal/findings"
)

// jsonEnvelope wraps the output with metadata.
type jsonEnvelope struct {
	GeneratedAt string             `json:"generated_at"`
	Count       int                `json:"count"`
	Findings    []findings.Finding `json:"findings"`
}

// JSONRenderer writes findings as pretty-printed JSON.
type JSONRenderer struct{}

// Compile-time check: JSONRenderer satisfies Renderer.
var _ Renderer = (*JSONRenderer)(nil)

func (r *JSONRenderer) Render(_ context.Context, f []findings.Finding, w io.Writer) error {
	if f == nil {
		f = []findings.Finding{}
	}

	env := jsonEnvelope{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Count:       len(f),
		Findings:    f,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	if err := enc.Encode(env); err != nil {
		return fmt.Errorf("json render: %w", err)
	}

	return nil
}
