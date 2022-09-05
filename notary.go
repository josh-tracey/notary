package notary

import "github.com/golang-jwt/jwt/v4"

type Notary struct {
	secret string
}

func New(secret string) *Notary {
	return &Notary{secret: secret}
}

func (n *Notary) VerifyToken(token string) (bool, error) {
	_, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(n.secret), nil
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

func (n *Notary) NewSignedToken() (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	tokenString, err := token.SignedString([]byte(n.secret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
