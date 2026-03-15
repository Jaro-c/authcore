package password

import "errors"

// ErrInvalidConfig is returned by New when the provided Config fails validation.
var ErrInvalidConfig = errors.New("password: invalid config")

// ErrInvalidHash is returned by Verify when the stored hash is not a valid
// Argon2id PHC string produced by this module.
var ErrInvalidHash = errors.New("password: invalid hash format")

// ErrWeakPassword is returned by Hash when the plaintext password does not
// satisfy the built-in policy. Wrap-check with errors.Is; inspect the message
// for the specific requirement that failed.
var ErrWeakPassword = errors.New("password: does not meet policy requirements")
