package middleware

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

type basicAuth struct {
	h    http.Handler
	opts AuthOptions
}

// AuthOptions stores the configuration for HTTP Basic Authentication.
//
// A http.Handler may also be passed to UnauthorizedHandler to override the
// default error handler if you wish to serve a custom template/response.
type AuthOptions struct {
	Realm               string
	User                string
	Password            string
	UnauthorizedHandler http.Handler
	// Advanced users can supply a custom user:password comparison function
	Validate func(string, string) bool
}

// Satisfies the http.Handler interface for basicAuth.
func (b basicAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if we have a user-provided error handler, else set a default
	if b.opts.UnauthorizedHandler == nil {
		b.opts.UnauthorizedHandler = http.HandlerFunc(defaultUnauthorizedHandler)
		return
	}

	// Set a default user/password validation function
	if b.opts.Validate == nil {
		b.opts.Validate = b.validate
	}

	// Check that the provided details match
	if b.authenticate(r) == false {
		b.requestAuth(w, r)
		return
	}

	// Call the next handler on success.
	b.h.ServeHTTP(w, r)
}

// authenticate validates the user:password combination provided in the request header.
// Returns 'false' if the user has not successfully authenticated.
func (b *basicAuth) authenticate(r *http.Request) bool {

	const basicScheme string = "Basic "

	// Confirm the request is sending Basic Authentication credentials.
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, basicScheme) {
		return false
	}

	// Get the plain-text username and password from the request
	// The first six characters are skipped e.g. "Basic ".
	str, err := base64.StdEncoding.DecodeString(auth[len(basicScheme):])
	if err != nil {
		return false
	}

	// Split on the first ":" character only, with any subsequent colons assumed to be part
	// of the password. Note that the RFC2617 standard does not place any limitations on
	// allowable characters in the password.
	creds := strings.SplitN(string(str), ":", 2)
	// Validate the user & password match.
	if b.validate(creds[0], creds[1]) == true {
		return true
	}

	return false
}

// Validate that the provided user & password match.
func (b *basicAuth) validate(user string, password string) bool {
	if user == b.opts.User && password == b.opts.Password {
		return true
	}

	return false
}

// Require authentication, and serve our error handler otherwise.
func (b *basicAuth) requestAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%q"`, b.opts.Realm))
	b.opts.UnauthorizedHandler.ServeHTTP(w, r)
}

// defaultUnauthorizedHandler provides a default HTTP 401 Unauthorized response.
func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

// BasicAuth provides HTTP middleware for protecting URIs with HTTP Basic Authentication
// as per RFC 2617. The server authenticates a user:password combination provided in the
// "Authorization" HTTP header.
//
// Example:
//
//     package main
//
//     import(
//            "net/http"
//            "github.com/zenazn/goji/web"
//            "github.com/zenazn/goji/web/middleware"
//     )
//
//     func main() {
//          basicOpts := &middleware.AuthOptions{
//                      Realm: "Restricted",
//                      User: "Dave",
//                      Password: "ClearText",
//                  }
//
//          goji.Use(middleware.BasicAuth(basicOpts), middleware.SomeOtherMiddleware)
//          goji.Get("/thing", myHandler)
//  }
//
// Note: HTTP Basic Authentication credentials are sent in plain text, and therefore it does
// not make for a wholly secure authentication mechanism. You should serve your content over
// HTTPS to mitigate this, noting that "Basic Authentication" is meant to be just that: basic!
func BasicAuth(o AuthOptions) func(http.Handler) http.Handler {
	fn := func(h http.Handler) http.Handler {
		return basicAuth{h, o}
	}
	return fn
}

// SimpleBasicAuth is a convenience wrapper around BasicAuth. It takes a user and password, and
// returns a pre-configured BasicAuth handler using the "Restricted" realm and a default 401 handler.
//
// Example:
//
//     package main
//
//     import(
//            "net/http"
//            "github.com/zenazn/goji/web"
//            "github.com/zenazn/goji/web/middleware"
//     )
//
//     func main() {
//
//          goji.Use(httpauth.SimpleBasicAuth("dave", "somepassword"), middleware.SomeOtherMiddleware)
//          goji.Get("/thing", myHandler)
//      }
//
func SimpleBasicAuth(user, password string) func(http.Handler) http.Handler {
	opts := AuthOptions{
		Realm:    "Restricted",
		User:     user,
		Password: password,
	}
	return BasicAuth(opts)
}