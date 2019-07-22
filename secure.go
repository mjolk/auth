package auth

import (
	"context"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
	"time"

	uuid "github.com/gofrs/uuid"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type userKey int

type userLoadFunc = func(context.Context, uuid.UUID) (Login, error)
type userFindFunc = func(context.Context, string) (Login, error)

type AuthConfig struct {
	AuthorizationHeader string
	LoginValidator      *regexp.Regexp
	TTL                 int
	Issuer              string
	Audience            []string
	Expiration          time.Duration
	LoadLogin           userLoadFunc
	FindLogin           userFindFunc
	PrivateKeyFile      string
	PublicKeyFile       string
}

type Login interface {
	ID() uuid.UUID
	Password() []byte
	Email() string
	Expires() time.Time
}

const (
	ttl                 = 168
	authorizationHeader = "BP-REGISTRATION"
	emailRegex          = `(\w[-._\w]*\w@\w[-._\w]*\w\.\w{2,3})`
)

var (
	emailMatcher, _ = regexp.Compile(emailRegex) //should not return error O-o
	Config          = AuthConfig{
		AuthorizationHeader: authorizationHeader,
		LoginValidator:      emailMatcher,
		TTL:                 ttl,
		Issuer:              "mycompany.com",
		Expiration:          time.Duration(1) * time.Hour,
		PrivateKeyFile:      "server.key",
		PublicKeyFile:       "server.crt",
	}
	privKey   *rsa.PrivateKey
	pubKey    *rsa.PublicKey
	encrypter jose.Encrypter
	signer    jose.Signer
	uKey      userKey = 1
)

// Authentication authentication data user
type Authentication struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthenticationResponse struct {
	Token string    `json:"token"`
	User  uuid.UUID `json:"user"`
}

// AuthUser param context.Context returns logged in user
func User(ctx context.Context) Login {
	user, ok := ctx.Value(uKey).(Login)
	if !ok {
		//todo push error to logger
		return nil
	}
	return user
}

func Setup(_ context.Context) {
	errCh := make(chan error)
	loaded := make(chan struct{})
	go func() {
		if err := setPublicKey(); err != nil {
			errCh <- err
			return
		}
		loaded <- struct{}{}
	}()
	go func() {
		if err := setPrivateKey(); err != nil {
			errCh <- err
			return
		}
		loaded <- struct{}{}
	}()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			panic(fmt.Sprintf(
				"could not start service: %s",
				err,
			))
		case <-loaded:
		}
	}
	var err error
	encrypter, err = jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{
			Algorithm: jose.RSA_OAEP_256,
			Key:       pubKey,
		},
		(&jose.EncrypterOptions{}).
			WithType("JWT").
			WithContentType("JWT"),
	)
	if err != nil {
		panic(fmt.Sprintf(
			"could not create encrypter: %s",
			err,
		))
	}
	signer, err = jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.PS256,
			Key:       privKey,
		},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		panic(fmt.Sprintf("could not create signer: %s", err))
	}
}

func setPublicKey() (err error) {
	var data []byte

	data, err = ioutil.ReadFile(Config.PublicKeyFile)
	if err != nil {
		return
	}

	pubKey, err = ParseRSAPublicKeyFromPEM(data)
	if err != nil {
		return
	}

	return
}

func setPrivateKey() (err error) {
	var data []byte

	data, err = ioutil.ReadFile(Config.PrivateKeyFile)
	if err != nil {
		return
	}

	privKey, err = ParseRSAPrivateKeyFromPEM(data)
	if err != nil {
		return
	}

	return
}

func createToken(id uuid.UUID, expires time.Time) (string, error) {
	cl := jwt.Claims{
		Subject:  id.String(),
		Issuer:   Config.Issuer,
		Expiry:   jwt.NewNumericDate(expires),
		Audience: Config.Audience,
	}
	return jwt.SignedAndEncrypted(signer, encrypter).
		Claims(cl).CompactSerialize()
}

func validateToken(
	ctx context.Context,
	tokenString string,
) (Login, error) {
	tok, err := jwt.ParseSignedAndEncrypted(tokenString)
	if err != nil {
		return nil, err
	}
	nested, err := tok.Decrypt(privKey)
	if err != nil {
		return nil, err
	}
	cl := jwt.Claims{}
	if err := nested.Claims(pubKey, &cl); err != nil {
		return nil, err
	}
	if err := cl.Validate(jwt.Expected{
		Issuer:   Config.Issuer,
		Time:     time.Now(),
		Audience: Config.Audience,
	}); err != nil {
		return nil, err
	}
	id, err := uuid.FromString(cl.Subject)
	if err != nil {
		return nil, err
	}
	return Config.LoadLogin(ctx, id)
}

func Context(ctx context.Context, user Login) context.Context {
	return context.WithValue(ctx, uKey, user)
}

func checkHeader(header string) (string, error) {
	herr := fmt.Errorf("incorrect authorization header")
	hlen := len(Config.AuthorizationHeader)
	if header == "" {
		return "", herr
	}
	if len(header) < hlen {
		return "", herr
	}
	if strings.ToUpper(header[:hlen]) != authorizationHeader {
		return "", herr
	}
	return header[hlen:], nil
}
