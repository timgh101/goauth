package goauth

import (
	"testing"
	"time"
)

func TestMain(t *testing.T) {
	secret := []byte("somesecret")

	customClaims := map[string]interface{}{
		"keyTest": "valTest",
	}
	token, err := Create(customClaims, time.Hour, secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) < 10 {
		t.Fatal("token len was < 10")
	}

	decodedClaims, err := VerifyAndDecode(token, secret)
	if err != nil {
		t.Fatal(err)
	}

	if decodedClaims["keyTest"] == nil {
		t.Fatal("decodedClaims didn't have the key expected")
		return
	}

	if decodedClaims["keyTest"] != "valTest" {
		t.Fatal("keyTest != valTest")
		return
	}

	t.Log(decodedClaims)

}

func TestTokenExpiry(t *testing.T) {
	secret := []byte("somesecret")

	customClaims := map[string]interface{}{
		"keyTest": "valTest",
	}
	token, err := Create(customClaims, time.Nanosecond, secret)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Nanosecond * 3)

	_, err = VerifyAndDecode(token, secret)
	if err == nil {
		t.Fatal("expected error from out of date token")
	}

	if err.Error() != "token expired" {
		t.Fatal("got an error but it wasn't   'token expired'  ")
	}

}

func TestCreateUnhappy(t *testing.T) {
	tests := []struct {
		name        string
		secret      string
		token       string
		lifeTime    time.Duration
		claims      map[string]interface{}
		errExpected bool
	}{
		{
			name:     "normal",
			secret:   "somesecret",
			token:    "",
			lifeTime: time.Hour,
			claims: map[string]interface{}{
				"testKey": "testVal",
			},
			errExpected: false,
		},
		{
			name:     "blank secret",
			secret:   "",
			token:    "",
			lifeTime: time.Hour,
			claims: map[string]interface{}{
				"testKey": "testVal",
			},
			errExpected: true,
		},
	}

	for _, test := range tests {
		bsecret := []byte(test.secret)

		_, err := Create(test.claims, test.lifeTime, bsecret)
		if err != nil {
			if !test.errExpected {
				t.Fatal(err, test.name)
			}
		}

		if err == nil {
			if test.errExpected {
				t.Fatal("error was nil when expected err. Test name: ", test.name)
			}
		}

	}

}

func TestValidateUnhappy(t *testing.T) {

	tests := []struct {
		name        string
		secret      string
		token       string
		lifeTime    time.Duration
		claims      map[string]interface{}
		errExpected bool
	}{
		{
			name:     "normal",
			secret:   "somesecret",
			token:    "",
			lifeTime: time.Hour,
			claims: map[string]interface{}{
				"testKey": "testVal",
			},
			errExpected: false,
		},
		{
			name:     "expires immediately",
			secret:   "somesecret",
			token:    "",
			lifeTime: time.Nanosecond * 0,
			claims: map[string]interface{}{
				"testKey": "testVal",
			},
			errExpected: true,
		},
	}

	for _, test := range tests {
		bsecret := []byte(test.secret)

		token, _ := Create(test.claims, test.lifeTime, bsecret)

		_, err := VerifyAndDecode(token, bsecret)
		if err != nil {
			if !test.errExpected {
				t.Fatal(err, test.name)
			}
		}

		if err == nil {
			if test.errExpected {
				t.Fatal("error was nil when expected err. Test name: ", test.name)
			}
		}

	}

	// dodgy secret
	claims := map[string]interface{}{
		"testKey": "testVal",
	}
	bsecret := []byte("somesecret")
	token, err := Create(claims, time.Hour, bsecret)
	if err != nil {
		t.Fatal("error while getting token while testing dodgy stuff")
	}
	_, err = VerifyAndDecode(token, []byte("someothersecret"))
	if err == nil {
		t.Fatal("should of gotten an error while verifying withh dodgy secret")
	}

	// dodgy token
	token = token + "a"
	_, err = VerifyAndDecode(token, bsecret)
	if err == nil {
		t.Fatal("should of gotten an error while verifying dodgy token")
	}

}
