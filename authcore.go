// Package authcore provides a modular, production-ready authentication library for Go.
//
// # Quick start
//
//	cfg := authcore.DefaultConfig()
//	auth, err := authcore.New(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Modules
//
// Future authentication mechanisms are organised under the auth/ sub-tree:
//
//	auth/jwt    — JSON Web Tokens
//	auth/apikey — opaque API key validation
//	auth/oauth  — OAuth 2.0 / OIDC
//
// Each module receives the parent *AuthCore so it can share configuration
// and the logger without duplicating state.
package authcore

import "fmt"

// AuthCore is the central object of the library.
// It holds shared configuration and the logger, and is the entry point for
// all authentication sub-modules.
//
// Create one instance per application; it is safe for concurrent use.
type AuthCore struct {
	config Config
	log    Logger
}

// New creates and returns a fully initialised *AuthCore.
//
// cfg is merged with defaults so callers can pass a partially-filled Config:
//
//	// Minimal usage — all defaults apply.
//	auth, err := authcore.New(authcore.DefaultConfig())
//
//	// Custom timezone, logs disabled.
//	cfg := authcore.DefaultConfig()
//	cfg.Timezone = time.UTC
//	cfg.EnableLogs = false
//	auth, err := authcore.New(cfg)
//
// New returns ErrInvalidConfig (or a wrapped sentinel) on bad input.
func New(cfg Config) (*AuthCore, error) {
	cfg = applyDefaults(cfg)

	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	logger := newLogger(cfg)

	ac := &AuthCore{
		config: cfg,
		log:    logger,
	}

	ac.log.Info("authcore initialised (timezone=%s, logs=%v)", cfg.Timezone, cfg.EnableLogs)

	return ac, nil
}

// Config returns a copy of the active configuration.
// Sub-modules should call this to read shared settings.
func (a *AuthCore) Config() Config {
	return a.config
}

// Logger returns the active Logger.
// Sub-modules should use this logger to write to the same sink as the core.
func (a *AuthCore) Logger() Logger {
	return a.log
}
