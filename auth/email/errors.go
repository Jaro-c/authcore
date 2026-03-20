package email

import "errors"

// Sentinel errors returned by the email package.
// Use errors.Is to check for these in calling code.
//
// # Error safety
//
// ErrInvalidEmail is CLIENT-SAFE: the wrapped reason describes exactly which
// rule failed and is suitable for returning in a 400 response:
//
//	normalized, err := emailMod.ValidateAndNormalize(req.Email)
//	if err != nil {
//	    c.JSON(400, map[string]string{"error": errors.Unwrap(err).Error()})
//	    return
//	}
var ErrInvalidEmail = errors.New("email: invalid address")

// emailViolation wraps ErrInvalidEmail with a single specific reason so that
// both errors.Is(err, ErrInvalidEmail) and errors.Unwrap(err) work correctly.
type emailViolation struct{ reason error }

func (v *emailViolation) Error() string   { return ErrInvalidEmail.Error() + ": " + v.reason.Error() }
func (v *emailViolation) Is(t error) bool { return t == ErrInvalidEmail }
func (v *emailViolation) Unwrap() error   { return v.reason }
