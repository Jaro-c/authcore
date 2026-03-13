// Package apikey will provide opaque API-key generation and validation for authcore.
//
// Status: planned — not yet implemented.
//
// Design notes:
//
//   - The constructor accepts an authcore.Provider (not *authcore.AuthCore)
//     so the module remains independently testable.
//   - Key generation will use internal/randutil (planned) for cryptographically
//     secure entropy.
//   - The Store interface will be defined within this package so callers can
//     adapt any backend (Redis, Postgres, in-memory) without importing extras.
//
// Intended API sketch:
//
//	keyMod, err := apikey.New(provider, apikey.Config{
//	    Store:  redisStore,  // implements apikey.Store
//	    Prefix: "sk_live_",
//	    Length: 32,
//	})
//
//	key,  err := keyMod.Generate(ctx, metadata)
//	meta, err := keyMod.Validate(ctx, rawKey)
//
//	func (k *APIKey) Name() string { return "apikey" }  // implements authcore.Module
package apikey
