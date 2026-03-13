package authcore

import "time"

// Config holds the top-level configuration for an AuthCore instance.
// Zero values are replaced by safe defaults via DefaultConfig or applyDefaults.
type Config struct {
	// EnableLogs controls whether the library emits log output.
	// Defaults to true.
	EnableLogs bool

	// Timezone is used for any time-sensitive operations inside the library.
	// Defaults to time.UTC.
	Timezone *time.Location

	// Logger allows callers to inject a custom logging backend
	// (e.g. slog, zap, zerolog). When set, EnableLogs is ignored.
	// If nil and EnableLogs is true, a default stdlib logger is used.
	Logger Logger
}

// DefaultConfig returns a Config populated with safe, production-ready defaults.
//
//	cfg := authcore.DefaultConfig()
//	cfg.EnableLogs = false          // disable logs for tests
//	auth, err := authcore.New(cfg)
func DefaultConfig() Config {
	return Config{
		EnableLogs: true,
		Timezone:   time.UTC,
	}
}

// applyDefaults fills zero-value fields in cfg with values from DefaultConfig.
func applyDefaults(cfg Config) Config {
	defaults := DefaultConfig()

	if cfg.Timezone == nil {
		cfg.Timezone = defaults.Timezone
	}
	// EnableLogs intentionally keeps its zero value (false) unless the caller
	// explicitly calls DefaultConfig or sets it to true. This prevents a
	// default-on behaviour that could surprise callers who pass an empty Config.
	return cfg
}

// validateConfig returns an error if cfg contains invalid values.
func validateConfig(cfg Config) error {
	if cfg.Timezone == nil {
		return ErrInvalidTimezone
	}
	return nil
}
