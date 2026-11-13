package apdu

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/paagoduura/provisioning/internal/domain"
)

type Channel interface {
	Send(context.Context, domain.ProvisioningSession, []byte) (string, error)
}
type Transport struct {
	Channel         Channel
	MaxPayloadBytes int
}

func (t Transport) Transfer(ctx context.Context, session domain.ProvisioningSession, wrapped string) error {
	if t.Channel == nil {
		return errors.New("APDU secure-channel transport is not configured")
	}
	if wrapped == "" {
		return errors.New("wrapped payload is empty")
	}
	payload, err := base64.RawURLEncoding.DecodeString(wrapped)
	if err != nil {
		return fmt.Errorf("decode wrapped APDU payload: %w", err)
	}
	max := t.MaxPayloadBytes
	if max <= 0 {
		max = 4096
	}
	if len(payload) > max {
		return errors.New("wrapped APDU payload exceeds configured limit")
	}
	_, err = t.Channel.Send(ctx, session, payload)
	return err
}

var _ interface {
	Transfer(context.Context, domain.ProvisioningSession, string) error
} = Transport{}
