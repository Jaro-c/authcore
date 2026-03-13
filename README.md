# authcore

[![Go Reference](https://pkg.go.dev/badge/github.com/Jaro-c/authcore.svg)](https://pkg.go.dev/github.com/Jaro-c/authcore)
[![Go Report Card](https://goreportcard.com/badge/github.com/Jaro-c/authcore)](https://goreportcard.com/report/github.com/Jaro-c/authcore)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/Jaro-c/authcore/actions/workflows/ci.yml/badge.svg)](https://github.com/Jaro-c/authcore/actions/workflows/ci.yml)

A modular, production-ready authentication library for Go 1.22+.

`authcore` provides a lightweight, extensible foundation for building authentication systems in Go. It's designed with security, testability, and developer experience in mind.

## Quick Start

```go
import "github.com/Jaro-c/authcore"

func main() {
    cfg := authcore.DefaultConfig()
    auth, err := authcore.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    
    // Use auth...
}
```

## Project Layout

```text
authcore/
├── authcore.go          # New() · AuthCore struct · compile-time interface checks
├── config.go            # Config · DefaultConfig()
├── logger.go            # Logger interface · stdlib and noop implementations
├── module.go            # Keys · Provider · Module interfaces
├── errors.go            # Sentinel errors
│
├── internal/
│   ├── clock/           # Timezone-aware Clock — shared by all modules
│   └── keymanager/      # Ed25519 + HMAC key generation, persistence, loading
│
├── auth/
│   ├── jwt/             # (planned) JSON Web Token authentication
│   ├── apikey/          # (planned) Opaque API-key authentication
│   └── oauth/           # (planned) OAuth 2.0 / OIDC
│
└── examples/
    └── basic/           # Runnable usage example
```

### Public vs Internal Packages

| Path | Visibility | Purpose |
|---|---|---|
| `github.com/Jaro-c/authcore` | **public** | Core types and entry point |
| `auth/jwt`, `auth/apikey`, `auth/oauth` | **public** | Auth modules, imported individually |
| `internal/clock` | **internal** | Shared timezone-aware time source |
| `internal/keymanager` | **internal** | Key generation and persistence |

## Configuration

```go
type Config struct {
    EnableLogs bool             // default: false — use DefaultConfig() for true
    Timezone   *time.Location   // default: time.UTC
    Logger     authcore.Logger  // optional: inject slog, zap, zerolog, …
    KeysDir    string           // default: ".authcore"
}
```

Start from `DefaultConfig()` and override only what you need:

```go
cfg := authcore.DefaultConfig()   // EnableLogs=true, Timezone=UTC
cfg.EnableLogs = false            // silence logs in tests
auth, err := authcore.New(cfg)
```

## Custom Logger

Implement the `Logger` interface to plug in any backend:

```go
type Logger interface {
    Debug(msg string, args ...any)
    Info(msg string, args ...any)
    Warn(msg string, args ...any)
    Error(msg string, args ...any)
}
```

When `Config.Logger` is non-nil, it takes precedence over `EnableLogs`.

## Key Management

On first run authcore creates `KeysDir` and generates:

| File | Description | Mode |
|---|---|---|
| `ed25519_private.pem` | PKCS#8 PEM signing key | `0600` |
| `ed25519_public.pem` | PKIX PEM verification key | `0644` |
| `refresh_secret.key` | 32-byte hex-encoded HMAC-SHA256 key | `0600` |
| `.gitignore` | Catch-all `*` — prevents accidental commits | `0600` |

On subsequent starts the files are loaded and the key pair is validated for consistency. If only one of the two PEM files is present `New()` returns `ErrKeyManager` — delete both to trigger regeneration.

**In containers or CI** point `KeysDir` at a mounted secrets volume:

```go
cfg.KeysDir = os.Getenv("AUTHCORE_KEYS_DIR") // e.g. /run/secrets/authcore
```

Sub-modules access key material through `Provider.Keys()`:

```go
privKey := p.Keys().PrivateKey()      // ed25519.PrivateKey — for signing
pubKey  := p.Keys().PublicKey()       // ed25519.PublicKey  — for verification
secret  := p.Keys().RefreshSecret()   // []byte (32)        — for HMAC-SHA256
```

## Writing a Module

Modules accept `authcore.Provider` (not `*authcore.AuthCore`) so they stay testable in isolation:

```go
// Provider is the narrow interface *AuthCore satisfies.
type Provider interface {
    Config() Config
    Logger() Logger
    Keys()   Keys
}

// Module is the marker interface every sub-module must implement.
type Module interface {
    Name() string
}
```

## Roadmap

- [ ] `auth/jwt`: Implementation of JWT authentication.
- [ ] `auth/apikey`: Opaque API key support.
- [ ] `auth/oauth`: OAuth2 and OIDC integration.

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

To report a vulnerability, please see our [Security Policy](SECURITY.md).

## License

This project is licensed under the [MIT License](LICENSE).

