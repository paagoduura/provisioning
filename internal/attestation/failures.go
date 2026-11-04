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
	FailureAndroidToken        = "ATTESTATION_ANDROID_TOKEN_INVALID"
	FailureAndroidRequest      = "ATTESTATION_ANDROID_REQUEST_MISMATCH"
	FailureAndroidPackage      = "ATTESTATION_ANDROID_PACKAGE_MISMATCH"
	FailureAndroidFreshness    = "ATTESTATION_ANDROID_TOKEN_NOT_FRESH"
	FailureAndroidVerdict      = "ATTESTATION_ANDROID_VERDICT_REJECTED"
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
	case errors.Is(err, ErrInvalidAttestationRegistration):
		return FailureInvalidRequest
	case errors.Is(err, ErrUnsupportedProvider):
		return FailureProviderUnavailable
	case errors.Is(err, ErrHSMUnavailable):
		return FailureHSMUnavailable
	case errors.Is(err, ErrAndroidInvalidToken), errors.Is(err, ErrAndroidDecodeFailed):
		return FailureAndroidToken
	case errors.Is(err, ErrAndroidRequestMismatch):
		return FailureAndroidRequest
	case errors.Is(err, ErrAndroidPackageMismatch):
		return FailureAndroidPackage
	case errors.Is(err, ErrAndroidTokenExpired):
		return FailureAndroidFreshness
	case errors.Is(err, ErrAndroidAppUnrecognized), errors.Is(err, ErrAndroidAccountUnlicensed), errors.Is(err, ErrAndroidDeviceIntegrity):
		return FailureAndroidVerdict
	default:
		return FailureVerification
	}
}
