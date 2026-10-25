package attestation

import "errors"

const (
	FailureInvalidRequest      = "ATTESTATION_INVALID_REQUEST"
	FailureChallengeNotFound   = "ATTESTATION_CHALLENGE_NOT_FOUND"
	FailureChallengeExpired    = "ATTESTATION_CHALLENGE_EXPIRED"
	FailureChallengeUsed       = "ATTESTATION_CHALLENGE_REPLAY"
	FailureRequestBinding      = "ATTESTATION_REQUEST_BINDING_MISMATCH"
	FailureCounterRollback     = "ATTESTATION_COUNTER_ROLLBACK"
	FailureDeviceRevoked       = "ATTESTATION_DEVICE_REVOKED"
	FailureProviderUnavailable = "ATTESTATION_PROVIDER_UNAVAILABLE"
	FailureHSMUnavailable      = "ATTESTATION_HSM_UNAVAILABLE"
	FailureVerification        = "ATTESTATION_VERIFICATION_FAILED"
	FailurePersistence         = "ATTESTATION_PERSISTENCE_FAILED"
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
	case errors.Is(err, ErrDeviceRevoked):
		return FailureDeviceRevoked
	case errors.Is(err, ErrUnsupportedProvider):
		return FailureProviderUnavailable
	case errors.Is(err, ErrHSMUnavailable):
		return FailureHSMUnavailable
	default:
		return FailureVerification
	}
}
