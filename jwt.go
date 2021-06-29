package goauth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

func Create(claims map[string]interface{}, lifeTime time.Duration, secret []byte) (string, error) {
	if len(secret) < 1 {
		return "", errors.New("secret not strong enough")
	}

	var c jwt.MapClaims = jwt.MapClaims{}
	expiry := time.Now().Add(lifeTime)

	for key, el := range claims {
		c[key] = el
	}
	c["expiry"] = expiry
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}
	return tokenString, nil

}

func VerifyAndDecode(token string, secret []byte) (map[string]interface{}, error) {

	decodedClaims := map[string]interface{}{}

	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return secret, nil
	})

	if claims, ok := t.Claims.(jwt.MapClaims); ok && t.Valid {
		for key, el := range claims {
			decodedClaims[key] = el
		}
	} else {
		return nil, err
	}

	if decodedClaims["expiry"] == nil {
		return nil, errors.New("token expired")
	}

	decodedExpiry, ok := decodedClaims["expiry"].(string)
	if !ok {
		return nil, errors.New("error parsing time")
	}

	expiry, err := time.Parse(time.RFC3339, decodedExpiry)
	if err != nil {
		return nil, err
	}

	if !expiry.After(time.Now()) {
		return nil, errors.New("token expired")
	}

	return decodedClaims, nil
}
