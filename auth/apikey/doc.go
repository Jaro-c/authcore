// Package apikey will provide opaque API-key generation and validation for authcore.
//
// Status: planned — not yet implemented.
//
// Intended API sketch:
//
//	keyModule := apikey.New(auth, apikey.Config{
//	    Store:  redisStore,   // implements apikey.Store
//	    Prefix: "sk_live_",
//	    Length: 32,
//	})
//
//	key, err  := keyModule.Generate(ctx, metadata)
//	meta, err := keyModule.Validate(ctx, rawKey)
package apikey
