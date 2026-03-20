package email

import (
	"errors"
	"testing"

	"github.com/Jaro-c/authcore"
)

// ---- test helpers -----------------------------------------------------------

type fakeProvider struct{}

func (fakeProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (fakeProvider) Logger() authcore.Logger  { return silentLogger{} }
func (fakeProvider) Keys() authcore.Keys      { return nil }

type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

func newMod(t *testing.T) *Email {
	t.Helper()
	m, err := New(fakeProvider{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// ---- New() ------------------------------------------------------------------

func TestNew_succeeds(t *testing.T) {
	if _, err := New(fakeProvider{}); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestName(t *testing.T) {
	if got := newMod(t).Name(); got != "email" {
		t.Errorf("Name() = %q, want %q", got, "email")
	}
}

// ---- Normalize() ------------------------------------------------------------

func TestNormalize_lowercases(t *testing.T) {
	m := newMod(t)
	if got := m.Normalize("USER@EXAMPLE.COM"); got != "user@example.com" {
		t.Errorf("got %q", got)
	}
}

func TestNormalize_trimsSpaces(t *testing.T) {
	m := newMod(t)
	if got := m.Normalize("  user@example.com  "); got != "user@example.com" {
		t.Errorf("got %q", got)
	}
}

func TestNormalize_mixedCaseAndSpaces(t *testing.T) {
	m := newMod(t)
	if got := m.Normalize("  Ana@Example.COM  "); got != "ana@example.com" {
		t.Errorf("got %q", got)
	}
}

// ---- Validate() — valid addresses -------------------------------------------

func TestValidate_simpleValid(t *testing.T) {
	valid := []string{
		"user@example.com",
		"user.name@example.com",
		"user+tag@example.co.uk",
		"a@b.io",
		"user@sub.domain.example.com",
	}
	m := newMod(t)
	for _, addr := range valid {
		if err := m.Validate(addr); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", addr, err)
		}
	}
}

// ---- Validate() — invalid addresses -----------------------------------------

func TestValidate_empty(t *testing.T) {
	if err := newMod(t).Validate(""); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_tooLong(t *testing.T) {
	// 255-character address
	local := "a"
	for len(local+"@b.com") <= 254 {
		local += "a"
	}
	if err := newMod(t).Validate(local + "@b.com"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail for too-long address")
	}
}

func TestValidate_noAt(t *testing.T) {
	if err := newMod(t).Validate("userexample.com"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_localPartTooLong(t *testing.T) {
	local := ""
	for i := 0; i < 65; i++ {
		local += "a"
	}
	if err := newMod(t).Validate(local + "@example.com"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail for local part > 64 chars")
	}
}

func TestValidate_domainNoDot(t *testing.T) {
	if err := newMod(t).Validate("user@localhost"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_domainLeadingDot(t *testing.T) {
	if err := newMod(t).Validate("user@.example.com"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_domainTrailingDot(t *testing.T) {
	if err := newMod(t).Validate("user@example.com."); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_domainConsecutiveDots(t *testing.T) {
	if err := newMod(t).Validate("user@example..com"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_withDisplayName(t *testing.T) {
	if err := newMod(t).Validate("Ana <ana@example.com>"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail for display name format")
	}
}

// ---- Validate() — ErrInvalidEmail wraps a reason ---------------------------

func TestValidate_wrapsReason(t *testing.T) {
	err := newMod(t).Validate("")
	if !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("expected ErrInvalidEmail, got %v", err)
	}
	reason := errors.Unwrap(err)
	if reason == nil {
		t.Fatal("expected wrapped reason, got nil")
	}
	if reason.Error() == "" {
		t.Error("wrapped reason must not be empty")
	}
}

// ---- ValidateAndNormalize() -------------------------------------------------

func TestValidateAndNormalize_normalizes(t *testing.T) {
	m := newMod(t)
	got, err := m.ValidateAndNormalize("  USER@EXAMPLE.COM  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "user@example.com" {
		t.Errorf("got %q, want %q", got, "user@example.com")
	}
}

func TestValidateAndNormalize_invalidReturnsError(t *testing.T) {
	_, err := newMod(t).ValidateAndNormalize("not-an-email")
	if !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidateAndNormalize_emptyReturnsError(t *testing.T) {
	_, err := newMod(t).ValidateAndNormalize("")
	if !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}
