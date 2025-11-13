package security

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// ParseUnverifiedJWT parses JWT and returns its claims
// but DOES NOT verify the signature.
//
// It verifies only the exp, iat and nbf claims.
func ParseUnverifiedJWT(token string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}

	parser := &jwt.Parser{}
	_, _, err := parser.ParseUnverified(token, claims)

	if err == nil {
		err = claims.Valid()
	}

	return claims, err
}

// // ParseJWT verifies and parses JWT and returns its claims.
// func ParseJWT(token string, verificationKey string) (jwt.MapClaims, error) {
// 	parser := jwt.NewParser(jwt.WithValidMethods([]string{"HS256"}))

// 	parsedToken, err := parser.Parse(token, func(t *jwt.Token) (any, error) {
// 		return []byte(verificationKey), nil
// 	})
// 	if err != nil {
// 		return nil, err
// 	}

// 	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
// 		return claims, nil
// 	}

// 	return nil, errors.New("Unable to parse token.")
// }

// ParseJWT verifies and parses JWT and returns its claims.
func old_ParseJWT(token string, oldVerificationKey string) (jwt.MapClaims, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(os.Getenv("JWT_PUBLIC_KEY")))
	if err != nil {
		return nil, err
	}

	parsedToken, err := parser.Parse(token, func(t *jwt.Token) (any, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		return claims, nil
	}

	return nil, errors.New("unable to parse token")
}

// // NewJWT generates and returns new HS256 signed JWT.
// func NewJWT(payload jwt.MapClaims, signingKey string, secondsDuration int64) (string, error) {
// 	seconds := time.Duration(secondsDuration) * time.Second

// 	claims := jwt.MapClaims{
// 		"exp": time.Now().Add(seconds).Unix(),
// 	}

// 	for k, v := range payload {
// 		claims[k] = v
// 	}

// 	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(signingKey))
// }

// NewJWT generates and returns new HS256 signed JWT.
func old_NewJWT(payload jwt.MapClaims, oldSigninKey string, secondsDuration int64) (string, error) {
	seconds := time.Duration(secondsDuration) * time.Second

	claims := jwt.MapClaims{
		"exp": time.Now().Add(seconds).Unix(),
	}

	for k, v := range payload {
		claims[k] = v
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(os.Getenv("JWT_PRIVATE_KEY")))
	if err != nil {
		return "", err
	}

	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
}

func ParseJWT(token string, oldVerificationKey string) (jwt.MapClaims, error) {
    parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))

    // Read public key from file
    publicKeyFile := os.Getenv("JWT_PUBLIC_KEY_FILE")
    if publicKeyFile == "" {
        return nil, errors.New("JWT_PUBLIC_KEY_FILE environment variable not set")
    }

    publicKeyPEM, err := os.ReadFile(publicKeyFile)
    if err != nil {
        return nil, fmt.Errorf("failed to read public key file: %w", err)
    }

    publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
    if err != nil {
        return nil, fmt.Errorf("failed to parse public key: %w", err)
    }

    parsedToken, err := parser.Parse(token, func(t *jwt.Token) (any, error) {
        return publicKey, nil
    })
    if err != nil {
        return nil, err
    }

    if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
        return claims, nil
    }

    return nil, errors.New("unable to parse token")
}

func NewJWT(payload jwt.MapClaims, oldSigninKey string, secondsDuration int64) (string, error) {
    seconds := time.Duration(secondsDuration) * time.Second

    claims := jwt.MapClaims{
        "exp": time.Now().Add(seconds).Unix(),
    }

    for k, v := range payload {
        claims[k] = v
    }

    // Read private key from file
    privateKeyFile := os.Getenv("JWT_PRIVATE_KEY_FILE")
    if privateKeyFile == "" {
        return "", errors.New("JWT_PRIVATE_KEY_FILE environment variable not set")
    }

    privateKeyPEM, err := os.ReadFile(privateKeyFile)
    if err != nil {
        return "", fmt.Errorf("failed to read private key file: %w", err)
    }

    privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
    if err != nil {
        return "", fmt.Errorf("failed to parse private key: %w", err)
    }

    return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
}

// Deprecated:
// Consider replacing with NewJWT().
//
// NewToken is a legacy alias for NewJWT that generates a HS256 signed JWT.
func NewToken(payload jwt.MapClaims, signingKey string, secondsDuration int64) (string, error) {
	//
	// return NewJWT(payload, signingKey, secondsDuration)
	return NewJWT(payload, signingKey, secondsDuration)
}
