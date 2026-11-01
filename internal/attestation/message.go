package attestation

// canonicalMessage is the exact byte sequence covered by every device
// signature. Keep this format versioned and stable: changing it invalidates
// all clients that sign attestation requests.
func canonicalMessage(challenge Challenge, input Submission) []byte {
	return []byte(challenge.Value + "\n" + input.RequestHash + "\n" + challenge.SessionID)
}
