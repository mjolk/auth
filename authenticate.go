package auth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/mjolk/net"
	"golang.org/x/crypto/bcrypt"
)

func authorize(
	ctx context.Context,
	r *http.Request,
) (context.Context, error) {
	ah := r.Header.Get("Authorization")
	tokenString, err := checkHeader(ah)
	if err != nil {
		return ctx, err
	}
	return validate(ctx, tokenString)
}

func authorizeURL(
	ctx context.Context,
	r *http.Request,
) (context.Context, error) {
	tokenString := r.FormValue("token")
	if tokenString == "" {
		return ctx, fmt.Errorf("No token")
	}
	return validate(ctx, tokenString)
}

func validate(
	ctx context.Context,
	tokenString string,
) (context.Context, error) {
	login, err := validateToken(ctx, tokenString)
	if err != nil {
		return ctx, err
	}
	if login.Expires().Before(time.Now()) {
		return context.TODO(), fmt.Errorf(" expired: %s", login.Expires().String())
	}
	return Context(ctx, login), nil
}

// Authorize authorize request decorator
func Authorize(endpoint net.EndPoint) net.EndPoint {
	return func(
		ctx context.Context,
		w http.ResponseWriter,
		r *http.Request,
	) {
		authCtx, err := authorize(ctx, r)
		if err != nil {
			log.Printf("error authorization: %s\n", err)
			net.NoAccess(w)
			return
		}
		endpoint(authCtx, w, r)
	}
}

func AuthorizeUrl(endpoint net.EndPoint) net.EndPoint {
	return func(
		ctx context.Context,
		w http.ResponseWriter,
		r *http.Request,
	) {
		authCtx, err := authorizeURL(ctx, r)
		if err != nil {
			log.Printf("error authorization: %s\n", err)
			net.NoAccess(w)
			return
		}
		endpoint(authCtx, w, r)
	}

}

func Authenticate(
	ctx context.Context,
	auth *Authentication,
) (*AuthenticationResponse, error) {
	if !emailMatcher.MatchString(auth.Email) {
		return nil, fmt.Errorf(
			"Malformed e-mail address %s",
			auth.Email,
		)
	}
	login, err := Config.SearchLogin(ctx, auth.Email)
	if err := bcrypt.CompareHashAndPassword(
		login.Password(),
		[]byte(auth.Password),
	); err != nil {
		return nil, err
	}
	token, err := createToken(
		login.ID(),
		time.Now().Add(time.Duration(1)*time.Hour),
	)
	if err != nil {
		return nil, err
	}
	return &AuthenticationResponse{
		Token: token,
		User:  login.ID(),
	}, nil
}
