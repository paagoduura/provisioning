package attestation

import "errors"

import "github.com/paagoduura/provisioning/internal/registry"

const (
	FailureInvalidRequest       = "ATTESTATION_INVALID_REQUEST"
	FailureChallengeNotFound    = "ATTESTATION_CHALLENGE_NOT_FOUND"
	FailureChallengeExpired     = "ATTESTATION_CHALLENGE_EXPIRED"
	FailureChallengeUsed        = "ATTESTATION_CHALLENGE_REPLAY"
	FailureRequestBinding       = "ATTESTATION_REQUEST_BINDING_MISMATCH"
	FailureCounterRollback      = "ATTESTATION_COUNTER_ROLLBACK"
	FailureDeviceRevoked        = "ATTESTATION_DEVICE_REVOKED"
	FailureProviderUnavailable  = "ATTESTATION_PROVIDER_UNAVAILABLE"
	FailureHSMUnavailable       = "ATTESTATION_HSM_UNAVAILABLE"
	FailureVerification         = "ATTESTATION_VERIFICATION_FAILED"
	FailureKMSKeyMismatch       = "ATTESTATION_KMS_KEY_MISMATCH"
	FailureKMSInvalidAssertion  = "ATTESTATION_KMS_INVALID_ASSERTION"
	FailureKMSInvalidSignature  = "ATTESTATION_KMS_SIGNATURE_INVALID"
	FailureGoogleUnavailable    = "ATTESTATION_GOOGLE_PLAY_UNAVAILABLE"
	FailureGoogleInvalidToken   = "ATTESTATION_GOOGLE_PLAY_INVALID_TOKEN"
	FailureGoogleInvalidVerdict = "ATTESTATION_GOOGLE_PLAY_VERDICT_INVALID"
	FailurePersistence          = "ATTESTATION_PERSISTENCE_FAILED"
	FailureDeviceNotOwned       = "ATTESTATION_DEVICE_NOT_OWNED"
	FailureDeviceUnavailable    = "ATTESTATION_DEVICE_UNAVAILABLE"
	FailureKeyBoundElsewhere    = "ATTESTATION_KEY_BOUND_ELSEWHERE"
)

func FailureCode(err error) string {
	switch {
	case errors.Is(err, ErrChallengeNotFound):
		return FailureChallengeNotFound
	case errors.Is(err, ErrChallengeExpired):
		return FailureChallengeExpired
	case errors.Is(err, ErrChallengeUsed):
		return FailureChallengeUsed
	case errors.Is(err, ErrRequestBinding):
		return FailureRequestBinding
	case errors.Is(err, ErrCounterRollback):
		return FailureCounterRollback
	case errors.Is(err, registry.ErrCounterRollback):
		return FailureCounterRollback
	case errors.Is(err, ErrDeviceRevoked):
		return FailureDeviceRevoked
	case errors.Is(err, registry.ErrDeviceNotFound), errors.Is(err, registry.ErrDeviceNotOwned):
		return FailureDeviceNotOwned
	case errors.Is(err, registry.ErrDeviceUnavailable), errors.Is(err, registry.ErrKeyRevoked), errors.Is(err, registry.ErrKeyReplaced):
		return FailureDeviceUnavailable
	case errors.Is(err, registry.ErrKeyBoundElsewhere):
		return FailureKeyBoundElsewhere
	case errors.Is(err, ErrUnsupportedProvider):
		return FailureProviderUnavailable
	case errors.Is(err, ErrHSMUnavailable):
		return FailureHSMUnavailable
	case errors.Is(err, ErrKMSUnavailable):
		return FailureHSMUnavailable
	case errors.Is(err, ErrKMSKeyMismatch):
		return FailureKMSKeyMismatch
	case errors.Is(err, ErrKMSInvalidAssertion):
		return FailureKMSInvalidAssertion
	case errors.Is(err, ErrKMSInvalidSignature):
		return FailureKMSInvalidSignature
	case errors.Is(err, ErrGooglePlayUnavailable):
		return FailureGoogleUnavailable
	case errors.Is(err, ErrGooglePlayInvalidAssertion):
		return FailureGoogleInvalidToken
	case errors.Is(err, ErrGooglePlayInvalidVerdict):
		return FailureGoogleInvalidVerdict
	default:
		return FailureVerification
	}
}
