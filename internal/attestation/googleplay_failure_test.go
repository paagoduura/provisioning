package attestation

import "testing"

func TestGooglePlayFailureCodes(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "unavailable", err: ErrGooglePlayUnavailable, want: FailureGoogleUnavailable},
		{name: "invalid token", err: ErrGooglePlayInvalidAssertion, want: FailureGoogleInvalidToken},
		{name: "invalid verdict", err: ErrGooglePlayInvalidVerdict, want: FailureGoogleInvalidVerdict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := FailureCode(test.err); got != test.want {
				t.Fatalf("FailureCode(%v) = %q, want %q", test.err, got, test.want)
			}
		})
	}
}
