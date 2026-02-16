package renderer

import (
	"context"
	"fmt"
	"io"

	"github.com/thiagohdeplima/riskctl/internal/findings"
)

// Renderer outputs findings in a specified format.
type Renderer interface {
	Render(ctx context.Context, findings []findings.Finding, output io.Writer) error
}

// StubRenderer is a stub that always returns not implemented.
type StubRenderer struct{}

func (s *StubRenderer) Render(_ context.Context, _ []findings.Finding, _ io.Writer) error {
	return fmt.Errorf("not implemented")
}
