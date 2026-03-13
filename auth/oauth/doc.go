// Package oauth will provide OAuth 2.0 / OIDC authentication for authcore.
//
// Status: planned — not yet implemented.
//
// Intended API sketch:
//
//	oauthModule := oauth.New(auth, oauth.Config{
//	    Provider:     oauth.Google,
//	    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
//	    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
//	    RedirectURL:  "https://example.com/callback",
//	    Scopes:       []string{"openid", "email", "profile"},
//	})
//
//	redirectURL := oauthModule.AuthCodeURL(state)
//	token, err  := oauthModule.Exchange(ctx, code)
//	user, err   := oauthModule.UserInfo(ctx, token)
package oauth
