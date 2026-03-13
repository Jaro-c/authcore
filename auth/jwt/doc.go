// Package jwt will provide JSON Web Token (JWT) authentication for authcore.
//
// Status: planned — not yet implemented.
//
// Intended API sketch:
//
//	jwtModule := jwt.New(auth, jwt.Config{
//	    Secret:    []byte(os.Getenv("JWT_SECRET")),
//	    Algorithm: jwt.HS256,
//	    TTL:       15 * time.Minute,
//	})
//
//	token, err := jwtModule.Sign(claims)
//	claims, err  := jwtModule.Verify(token)
package jwt
