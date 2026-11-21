package secret

import (
	"context"
	"errors"
)

// ErrDisabled is what the disabled Store answers: the deployment holds no secrets
// here, and the call fails closed.
var ErrDisabled = errors.New("cloud: dep \"kms\" is disabled — enable the subsystem or configure its RPC endpoint")

// Disabled returns the fail-closed Store of a deployment whose KMS is not available.
func Disabled() Store { return disabled{} }

type disabled struct{}

func (disabled) GetSecret(context.Context, string) ([]byte, error)    { return nil, ErrDisabled }
func (disabled) PutSecret(context.Context, string, []byte) error      { return ErrDisabled }
func (disabled) DeleteSecret(context.Context, string) error           { return ErrDisabled }
func (disabled) Sign(context.Context, string, []byte) ([]byte, error) { return nil, ErrDisabled }
