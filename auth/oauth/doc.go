// Package oauth will provide OAuth 2.0 / OIDC authentication for authcore.
//
// Status: planned — not yet implemented.
//
// Design notes:
//
//   - The constructor accepts an authcore.Provider (not *authcore.AuthCore)
//     so the module remains independently testable.
//   - CSRF state generation will use internal/randutil (planned) for
//     cryptographically secure random values.
//   - Provider-specific details (Google, GitHub, etc.) will be expressed as
//     named constants plus an escape-hatch custom config so users are not
//     locked to a predefined provider list.
//
// Intended API sketch:
//
//	oauthMod, err := oauth.New(provider, oauth.Config{
//	    Provider:     oauth.Google,
//	    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
//	    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
//	    RedirectURL:  "https://example.com/callback",
//	    Scopes:       []string{"openid", "email", "profile"},
//	})
//
//	redirectURL     := oauthMod.AuthCodeURL(state)
//	token, err      := oauthMod.Exchange(ctx, code)
//	userInfo, err   := oauthMod.UserInfo(ctx, token)
//
//	func (o *OAuth) Name() string { return "oauth" }  // implements authcore.Module
package oauth
