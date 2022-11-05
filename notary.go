package notary

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Notary interface {
	VerifyToken(token string) (bool, error)
	NewSignedToken() (string, error)
	isNotary()
}

type NotaryHS256 struct {
	secret string
}

type NotaryRS256 struct {
	privateKey []byte
	publicKey  []byte
}

func NewHS256(secret string) *NotaryHS256 {

	notary := &NotaryHS256{secret}
	return notary
}

func (n *NotaryHS256) isNotary() {}

func (n *NotaryHS256) VerifyToken(token string) (bool, error) {

	if token == "" {
		return false, nil
	}
	_, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(n.secret), nil
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

func (n *NotaryHS256) NewSignedToken() (string, error) {

	token := jwt.New(jwt.SigningMethodHS256)
	tokenString, err := token.SignedString([]byte(n.secret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func NewRS256(privateKey []byte, publicKey []byte) *NotaryRS256 {

	notary := &NotaryRS256{privateKey: privateKey, publicKey: publicKey}

	return notary
}

func (n *NotaryRS256) isNotary() {}

func (n *NotaryRS256) VerifyToken(token *string) (interface{}, error) {

	key, err := jwt.ParseRSAPublicKeyFromPEM(n.publicKey)
	if err != nil {
		return "", fmt.Errorf("create: parse key: %w", err)
	}

	if token == nil {
		return "", fmt.Errorf("Token is nil")
	}

	if *token == "" {
		return "", nil
	}

	tok, err2 := jwt.Parse(*token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", token.Header["alg"])
		}

		return key, nil
	})

	if err2 != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, fmt.Errorf("validate: invalid")
	}

	return claims["dat"], nil
}

func (n *NotaryRS256) NewSignedToken(ttl time.Duration, content interface{}) (string, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(n.privateKey)
	if err != nil {
		return "", fmt.Errorf("create: parse key: %w", err)
	}

	now := time.Now().UTC()

	claims := make(jwt.MapClaims)
	claims["dat"] = content             // Our custom data.
	claims["exp"] = now.Add(ttl).Unix() // The expiration time after which the token must be disregarded.
	claims["iat"] = now.Unix()          // The time at which the token was issued.
	claims["nbf"] = now.Unix()          // The time before which the token must be disregarded.

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return "", fmt.Errorf("create: sign token: %w", err)
	}

	return token, nil
}
