# authcore

A modular, production-ready authentication library for Go.

## Quick start

```go
import "github.com/Jaro-c/authcore"

cfg := authcore.DefaultConfig()
auth, err := authcore.New(cfg)
if err != nil {
    log.Fatal(err)
}
```

## Configuration

```go
type Config struct {
    EnableLogs bool             // default: true
    Timezone   *time.Location   // default: time.UTC
    Logger     authcore.Logger  // optional: inject your own logger (slog, zap, zerolog…)
}
```

Use `authcore.DefaultConfig()` as the starting point and override only what you need.

## Custom logger

Implement the `Logger` interface to plug in any logging backend:

```go
type Logger interface {
    Debug(msg string, args ...any)
    Info(msg string, args ...any)
    Warn(msg string, args ...any)
    Error(msg string, args ...any)
}
```

When `Config.Logger` is set, `Config.EnableLogs` is ignored.

## Project layout

```
authcore/
├── authcore.go          # New() constructor, AuthCore struct
├── config.go            # Config, DefaultConfig, validation
├── logger.go            # Logger interface, stdlib and noop implementations
├── errors.go            # Sentinel errors
│
├── auth/
│   ├── jwt/             # (planned) JSON Web Token authentication
│   ├── apikey/          # (planned) Opaque API-key authentication
│   └── oauth/           # (planned) OAuth 2.0 / OIDC
│
└── examples/
    └── basic/           # Runnable usage example
```

## Roadmap

| Module          | Status  |
|-----------------|---------|
| `auth/jwt`      | planned |
| `auth/apikey`   | planned |
| `auth/oauth`    | planned |

## License

MIT
