package authcore

import "errors"

// Sentinel errors returned by the authcore package.
var (
	// ErrInvalidConfig is returned when the supplied Config fails validation.
	ErrInvalidConfig = errors.New("authcore: invalid configuration")

	// ErrInvalidTimezone is returned when Config.Timezone is nil.
	ErrInvalidTimezone = errors.New("authcore: timezone must not be nil")
)
