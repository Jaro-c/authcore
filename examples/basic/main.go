// Command basic demonstrates how to initialise authcore with different
// configuration strategies.
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/Jaro-c/authcore"
)

func main() {
	// -------------------------------------------------------------------------
	// Example 1: use defaults (logs enabled, UTC timezone).
	// This is the recommended starting point for most applications.
	// -------------------------------------------------------------------------
	auth, err := authcore.New(authcore.DefaultConfig())
	if err != nil {
		log.Fatalf("failed to initialise authcore: %v", err)
	}

	fmt.Printf("timezone : %s\n", auth.Config().Timezone)
	fmt.Printf("logs on  : %v\n", auth.Config().EnableLogs)

	// -------------------------------------------------------------------------
	// Example 2: custom timezone, logs disabled (useful in tests or CLIs).
	// -------------------------------------------------------------------------
	bogota, err := time.LoadLocation("America/Bogota")
	if err != nil {
		log.Fatalf("unknown timezone: %v", err)
	}

	cfg := authcore.DefaultConfig()
	cfg.Timezone = bogota
	cfg.EnableLogs = false

	silentAuth, err := authcore.New(cfg)
	if err != nil {
		log.Fatalf("failed to initialise authcore: %v", err)
	}

	fmt.Printf("timezone : %s\n", silentAuth.Config().Timezone)
	fmt.Printf("logs on  : %v\n", silentAuth.Config().EnableLogs)

	// -------------------------------------------------------------------------
	// Example 3: inject a custom logger (e.g. wrap slog, zap, zerolog).
	// -------------------------------------------------------------------------
	cfg2 := authcore.DefaultConfig()
	cfg2.Logger = &myAppLogger{}

	customAuth, err := authcore.New(cfg2)
	if err != nil {
		log.Fatalf("failed to initialise authcore: %v", err)
	}

	// Logger() exposes the active logger so sub-modules can share the same sink.
	_ = customAuth.Logger()
}

// myAppLogger is a toy implementation of authcore.Logger.
// In a real application you would wrap slog, zap, or zerolog here.
type myAppLogger struct{}

func (myAppLogger) Debug(msg string, args ...any) { fmt.Printf("[DEBUG] "+msg+"\n", args...) }
func (myAppLogger) Info(msg string, args ...any)  { fmt.Printf("[INFO]  "+msg+"\n", args...) }
func (myAppLogger) Warn(msg string, args ...any)  { fmt.Printf("[WARN]  "+msg+"\n", args...) }
func (myAppLogger) Error(msg string, args ...any) { fmt.Printf("[ERROR] "+msg+"\n", args...) }
