// Package email provides email address validation and normalization for authcore.
//
// Validation follows RFC 5321 and RFC 5322 rules:
//   - Total length 1–254 characters
//   - Exactly one @ separating a non-empty local part and domain
//   - Local part ≤ 64 characters
//   - Domain contains at least one dot; no leading, trailing, or consecutive dots
//   - Each domain label is 1–63 characters
//
// Normalization lowercases and trims surrounding whitespace. Always normalize
// before storing and before querying — this ensures consistent lookup:
//
//	emailMod, _ := email.New(auth)
//
//	// Registration
//	normalized, err := emailMod.ValidateAndNormalize(req.Email)
//	if err != nil {
//	    c.JSON(400, map[string]string{"error": errors.Unwrap(err).Error()})
//	    return
//	}
//	db.StoreUser(normalized, ...)
//
//	// Login lookup
//	normalized, err := emailMod.ValidateAndNormalize(req.Email)
//	if err != nil { ... }
//	user := db.FindByEmail(normalized)
package email

import (
	"fmt"
	"net/mail"
	"strings"

	"github.com/Jaro-c/authcore"
)

// Email is the email validation and normalization module.
// Create one instance at startup via New and reuse it — it is safe for
// concurrent use.
type Email struct {
	log authcore.Logger
}

// New creates an Email module using the provider's logger.
func New(p authcore.Provider) (*Email, error) {
	e := &Email{log: p.Logger()}
	e.log.Info("email: module initialised")
	return e, nil
}

// Name implements authcore.Module.
func (e *Email) Name() string { return "email" }

// Normalize lowercases and trims surrounding whitespace from address.
// It does not validate — call Validate or ValidateAndNormalize for that.
func (e *Email) Normalize(address string) string {
	return strings.ToLower(strings.TrimSpace(address))
}

// Validate reports whether address is a well-formed email address.
// The address is expected to already be normalized (call Normalize first,
// or use ValidateAndNormalize to do both in one step).
//
// Returns nil on success, or [ErrInvalidEmail] wrapping the specific rule
// that failed. The wrapped reason is safe to show to the user.
func (e *Email) Validate(address string) error {
	return validate(address)
}

// ValidateAndNormalize normalizes address (lowercase + trim) and then
// validates it. Returns the normalized address on success.
//
// This is the recommended entry point for HTTP handlers:
//
//	normalized, err := emailMod.ValidateAndNormalize(req.Email)
//	if err != nil {
//	    c.JSON(400, map[string]string{"error": errors.Unwrap(err).Error()})
//	    return
//	}
func (e *Email) ValidateAndNormalize(address string) (string, error) {
	normalized := e.Normalize(address)
	if err := validate(normalized); err != nil {
		return "", err
	}
	return normalized, nil
}

// validate checks address against RFC 5321 / RFC 5322 rules.
// It uses net/mail for syntax and then applies stricter structural checks.
func validate(address string) error {
	if len(address) == 0 {
		return &emailViolation{reason: fmt.Errorf("must not be empty")}
	}
	if len(address) > 254 {
		return &emailViolation{reason: fmt.Errorf("must be at most 254 characters")}
	}

	// net/mail.ParseAddress handles RFC 5322 syntax (quoted strings, comments, etc.).
	parsed, err := mail.ParseAddress(address)
	if err != nil {
		return &emailViolation{reason: fmt.Errorf("invalid format")}
	}

	// Reject display names like "Ana García <ana@example.com>".
	// EqualFold is intentional: net/mail may normalize domain case, so a
	// direct == would reject valid addresses when Validate is called without
	// prior normalization (e.g. "User@EXAMPLE.COM" vs "User@example.com").
	if !strings.EqualFold(address, parsed.Address) {
		return &emailViolation{reason: fmt.Errorf("invalid format")}
	}

	atIdx := strings.LastIndexByte(parsed.Address, '@')
	local := parsed.Address[:atIdx]
	domain := parsed.Address[atIdx+1:]

	if len(local) > 64 {
		return &emailViolation{reason: fmt.Errorf("local part must be at most 64 characters")}
	}

	// Domain: at least one dot, no leading/trailing/consecutive dots,
	// each label 1–63 characters.
	hasDot := false
	labelLen := 0
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if labelLen == 0 {
				return &emailViolation{reason: fmt.Errorf("domain must not start with or contain consecutive dots")}
			}
			hasDot = true
			labelLen = 0
		} else {
			labelLen++
			if labelLen > 63 {
				return &emailViolation{reason: fmt.Errorf("each domain label must be at most 63 characters")}
			}
		}
	}
	if !hasDot {
		return &emailViolation{reason: fmt.Errorf("domain must contain at least one dot")}
	}
	if labelLen == 0 {
		return &emailViolation{reason: fmt.Errorf("domain must not end with a dot")}
	}

	return nil
}
