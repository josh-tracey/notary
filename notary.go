package notary

import (
	"crypto/rsa"
	"fmt"

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
	privateKey rsa.PrivateKey
	publicKey  rsa.PublicKey
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

func NewRS256(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *NotaryRS256 {

	PrivateKey := *privateKey
	PublicKey := *publicKey

	notary := &NotaryRS256{privateKey: PrivateKey, publicKey: PublicKey}

	return notary
}

func (n *NotaryRS256) isNotary() {}

func (n *NotaryRS256) VerifyToken(token string) (bool, error) {
	if token == "" {
		return false, nil
	}

	_, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", token.Header["alg"])
		}

		return &n.publicKey, nil
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

func (n *NotaryRS256) NewSignedToken() (string, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	tokenString, err := token.SignedString(&n.privateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
