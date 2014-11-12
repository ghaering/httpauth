package httpauth

import (
	"encoding/base64"
	"net/http"
	"testing"
)

func TestBasicAuthAuthenticate(t *testing.T) {
	// Provide a minimal test implementation.

	const correctUser = "test-user"
	const correctPassword = "plain-text-password"

	authOpts := AuthOptions{
		Realm: "Restricted",
		AuthFunc: func(user string, password string) bool {
			return user == correctUser && password == correctPassword
		},
	}

	b := &basicAuth{
		opts: authOpts,
	}

	r := &http.Request{}
	r.Method = "GET"

	// Provide auth data, but no Authorization header
	if b.authenticate(r) != false {
		t.Fatal("No Authorization header supplied.")
	}

	// Initialise the map for HTTP headers
	r.Header = http.Header(make(map[string][]string))

	// Set a malformed/bad header
	r.Header.Set("Authorization", "    Basic")
	if b.authenticate(r) != false {
		t.Fatal("Malformed Authorization header supplied.")
	}

	// Test correct credentials
	auth := base64.StdEncoding.EncodeToString([]byte(correctUser + ":" + correctPassword))
	r.Header.Set("Authorization", "Basic "+auth)
	if b.authenticate(r) != true {
		t.Fatal("Failed on correct credentials")
	}
}
