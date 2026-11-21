package infer

import (
	"context"
	"errors"
)

// ErrDisabled is what the disabled Client answers: the deployment configured no
// inference path, and the call fails closed.
var ErrDisabled = errors.New("cloud: dep \"ai\" is disabled — enable the subsystem or configure its RPC endpoint")

// Disabled returns the fail-closed Client of a deployment with no gateway, no IAM
// identity and no key: a run records an honest error, never a faked answer.
func Disabled() Client { return disabled{} }

type disabled struct{}

func (disabled) ChatCompletion(context.Context, *ChatRequest) (*ChatResponse, error) {
	return nil, ErrDisabled
}
func (disabled) Embed(context.Context, *EmbedRequest) ([][]float32, error) { return nil, ErrDisabled }
func (disabled) Rerank(context.Context, *RerankRequest) ([]float64, error) { return nil, ErrDisabled }
