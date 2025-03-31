package jwt

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v4"
	jujuErr "github.com/juju/errors"

	"github.com/go-jose/go-jose/v4/jose-util/generator"
	"github.com/loopfz/gadgeto/tonic"
	"github.com/youmark/pkcs8"
)

type AuthResponse struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
	Token   string `json:"token"`
	Expire  string `json:"expire"`
	Cookie  string `json:"cookie"`
}

type GeneratedToken struct {
	Token  string
	Expire time.Time
}

type Options struct {
	SignerName string
}

// GinJWTMiddleware provides a Json-Web-Token authentication implementation. On failure, a 401 HTTP response
// is returned. On success, the wrapped middleware is called, and the userID is made available as
// c.Get("userID").(string).
// Users can get a token by posting a json request to LoginHandler. The token then needs to be passed in
// the Authentication header. Example: Authorization:Bearer XXX_TOKEN_XXX
type GinJWTMiddleware[K interface{}] struct {
	// Realm name to display to the user. Required.
	Realm string

	DefaultOptions *Options
	DefaultSigner  *Signer

	// signing algorithm - possible values are HS256, HS384, HS512, RS256, RS384 or RS512
	// Optional, default is HS256.
	SigningAlgorithm string
	Signers          map[string]jose.Signer
	VerifierKeys     map[string]interface{}

	// Secret key used for signing. Required.
	Key  []byte
	Keys map[string]*Key
	// Callback to retrieve key used for signing. Setting KeyFunc will bypass
	// all other key settings
	KeyFunc func(token *jwt.Token) (interface{}, error)

	// Duration that a jwt token is valid. Optional, defaults to one hour.
	Timeout time.Duration
	// Callback function that will override the default timeout duration.
	TimeoutFunc func(data interface{}) time.Duration

	// This field allows clients to refresh their token until MaxRefresh has passed.
	// Note that clients can refresh their token in the last moment of MaxRefresh.
	// This means that the maximum validity timespan for a token is TokenTime + MaxRefresh.
	// Optional, defaults to 0 meaning not refreshable.
	MaxRefresh time.Duration

	// Callback function that should perform the authentication of the user based on login info.
	// Must return user data as user identifier, it will be stored in Claim Array. Required.
	// Check error (e) to determine the appropriate error message.
	Authenticator func(c *gin.Context, req K) (interface{}, error)

	// Callback function that should perform the authorization of the authenticated user. Called
	// only after an authentication success. Must return true on success, false on failure.
	// Optional, default to success.
	Authorizator func(data interface{}, c *gin.Context) bool

	// Callback function that will be called during login.
	// Using this function it is possible to add additional payload data to the webtoken.
	// The data is then made available during requests via c.Get("JWT_PAYLOAD").
	// Note that the payload is not encrypted.
	// The attributes mentioned on jwt.io can't be used as keys for the map.
	// Optional, by default no additional data will be set.
	PayloadFunc func(data interface{}) jwt.MapClaims

	// User can define own Unauthorized func.
	Unauthorized func(c *gin.Context, code int, message string)

	// User can define own LoginResponse func.
	LoginResponse func(c *gin.Context, code int, message string, time time.Time) (*AuthResponse, error)

	// User can define own LogoutResponse func.
	LogoutResponse func(c *gin.Context, code int) (*AuthResponse, error)

	// User can define own RefreshResponse func.
	RefreshResponse func(c *gin.Context, code int, message string, time time.Time) (*AuthResponse, error)

	// Set the identity handler function
	IdentityHandler func(*gin.Context) interface{}

	// Set the identity key
	IdentityKey string

	// TokenLookup is a string in the form of "<source>:<name>" that is used
	// to extract token from the request.
	// Optional. Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "cookie:<name>"
	TokenLookup string

	// TokenHeadName is a string in the header. Default value is "Bearer"
	TokenHeadName string

	// TimeFunc provides the current time. You can override it to use another time value. This is useful for testing or if your server uses a different time zone than your tokens.
	TimeFunc func() time.Time

	// HTTP Status messages for when something in the JWT middleware fails.
	// Check error (e) to determine the appropriate error message.
	HTTPStatusMessageFunc func(e error, c *gin.Context) string

	// Private key file for asymmetric algorithms
	PrivKeyFile map[string]string

	// Private Key bytes for asymmetric algorithms
	//
	// Note: PrivKeyFile takes precedence over PrivKeyBytes if both are set
	PrivKeyBytes map[string][]byte

	// Public key file for asymmetric algorithms
	PubKeyFile map[string]string

	// Private key passphrase
	PrivateKeyPassphrase string

	// Public key bytes for asymmetric algorithms.
	//
	// Note: PubKeyFile takes precedence over PubKeyBytes if both are set
	PubKeyBytes map[string][]byte

	// Private key
	privKey map[string]*rsa.PrivateKey

	// Public key
	pubKey map[string]*rsa.PublicKey

	// Optionally return the token as a cookie
	SendCookie bool

	// Duration that a cookie is valid. Optional, by default equals to Timeout value.
	CookieMaxAge time.Duration

	// Allow insecure cookies for development over http
	SecureCookie bool

	// Allow cookies to be accessed client side for development
	CookieHTTPOnly bool

	// Allow cookie domain change for development
	CookieDomain string

	// SendAuthorization allow return authorization header for every request
	SendAuthorization bool

	// Disable abort() of context.
	DisabledAbort bool

	// CookieName allow cookie name change for development
	CookieName string

	// CookieSameSite allow use http.SameSite cookie param
	CookieSameSite http.SameSite

	// ParseOptions allow to modify jwt's parser methods
	ParseOptions []jwt.ParserOption

	// Default vaule is "exp"
	ExpField string
}

var (
	// ErrMissingSecretKey indicates Secret key is required
	ErrMissingSecretKey = errors.New("secret key is required")

	// ErrForbidden when HTTP status 403 is given
	ErrForbidden = errors.New("you don't have permission to access this resource")

	// ErrMissingAuthenticatorFunc indicates Authenticator is required
	ErrMissingAuthenticatorFunc = errors.New("ginJWTMiddleware.Authenticator func is undefined")

	// ErrMissingLoginValues indicates a user tried to authenticate without username or password
	ErrMissingLoginValues = errors.New("missing Username or Password")

	// ErrFailedAuthentication indicates authentication failed, could be faulty username or password
	ErrFailedAuthentication = errors.New("incorrect Username or Password")

	// ErrFailedTokenCreation indicates JWT Token failed to create, reason unknown
	ErrFailedTokenCreation = errors.New("failed to create JWT Token")

	// ErrExpiredToken indicates JWT token has expired. Can't refresh.
	ErrExpiredToken = errors.New("token is expired") // in practice, this is generated from the jwt library not by us

	// ErrEmptyAuthHeader can be thrown if authing with a HTTP header, the Auth header needs to be set
	ErrEmptyAuthHeader = errors.New("auth header is empty")

	// ErrMissingExpField missing exp field in token
	ErrMissingExpField = errors.New("missing exp field")

	// ErrWrongFormatOfExp field must be float64 format
	ErrWrongFormatOfExp = errors.New("exp must be float64 format")

	// ErrInvalidAuthHeader indicates auth header is invalid, could for example have the wrong Realm name
	ErrInvalidAuthHeader = errors.New("auth header is invalid")

	// ErrEmptyQueryToken can be thrown if authing with URL Query, the query token variable is empty
	ErrEmptyQueryToken = errors.New("query token is empty")

	// ErrEmptyCookieToken can be thrown if authing with a cookie, the token cookie is empty
	ErrEmptyCookieToken = errors.New("cookie token is empty")

	// ErrEmptyParamToken can be thrown if authing with parameter in path, the parameter in path is empty
	ErrEmptyParamToken = errors.New("parameter token is empty")

	// ErrInvalidSigningAlgorithm indicates signing algorithm is invalid, needs to be HS256, HS384, HS512, RS256, RS384 or RS512
	ErrInvalidSigningAlgorithm = errors.New("invalid signing algorithm")

	// ErrNoPrivKeyFile indicates that the given private key is unreadable
	ErrNoPrivKeyFile = errors.New("private key file unreadable")

	// ErrNoPubKeyFile indicates that the given public key is unreadable
	ErrNoPubKeyFile = errors.New("public key file unreadable")

	// ErrInvalidPrivKey indicates that the given private key is invalid
	ErrInvalidPrivKey = errors.New("private key invalid")

	// ErrInvalidPubKey indicates the the given public key is invalid
	ErrInvalidPubKey = errors.New("public key invalid")

	// IdentityKey default identity key
	IdentityKey = "identity"
)

type Key struct {
	Data                 string
	PrivKeyFile          string
	PubKeyFile           string
	PrivateKeyPassphrase string
	IsJWK                bool
}

type Signer struct {
	Name string
	Keys []Key
}

type GeneratedKeys struct {
	Public  string
	Private string
}

// New for check error with GinJWTMiddleware
func New[K interface{}](m *GinJWTMiddleware[K], signers ...Signer) (*GinJWTMiddleware[K], error) {
	if err := m.MiddlewareInit(signers...); err != nil {
		return nil, err
	}

	return m, nil
}

func GenerateJWKSJsons() (*GeneratedKeys, error) {
	keyUsage := "sig"
	keyAlgorithm := jose.RS512
	publicKey, privateKey, err := generator.NewSigningKey(keyAlgorithm, 2048)
	if err != nil {
		return nil, err
	}

	publicKeyJwk := &jose.JSONWebKey{
		Key:       publicKey,
		Algorithm: string(keyAlgorithm),
		Use:       keyUsage,
	}

	privateKeyJwk := &jose.JSONWebKey{
		Key:       privateKey,
		Algorithm: string(keyAlgorithm),
		Use:       keyUsage,
	}

	publicKeyJwkBytes, err := publicKeyJwk.MarshalJSON()
	if err != nil {
		return nil, err
	}

	privateKeyJwkBytes, err := privateKeyJwk.MarshalJSON()
	if err != nil {
		return nil, err
	}

	return &GeneratedKeys{
		Public:  string(publicKeyJwkBytes),
		Private: string(privateKeyJwkBytes),
	}, nil
}

func (mw *GinJWTMiddleware[K]) readKey(
	signerName string,
	key Key,
) error {

	if key.IsJWK {
		return mw.readPublicKey(signerName, key)
	}

	err := mw.readPrivateKey(signerName, key)
	if err != nil {
		return err
	}

	err = mw.readPublicKey(signerName, key)
	if err != nil {
		return err
	}

	mw.Keys[signerName] = &key

	return nil
}

func (mw *GinJWTMiddleware[K]) readPrivateKey(
	signerName string,
	key Key,
) error {
	var keyData []byte
	var err error
	if key.PrivKeyFile == "" {
		keyData = []byte(key.Data)
	} else {
		var filecontent []byte
		filecontent, err = os.ReadFile(key.PrivKeyFile)
		if err != nil {
			return ErrNoPrivKeyFile
		}
		keyData = filecontent
	}

	if key.PrivateKeyPassphrase != "" {
		var parsed interface{}
		parsed, err = pkcs8.ParsePKCS8PrivateKey(keyData, []byte(key.PrivateKeyPassphrase))
		if err != nil {
			return ErrInvalidPrivKey
		}
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return ErrInvalidPrivKey
		}
		mw.privKey[signerName] = rsaKey
		return nil
	}

	var parsed *rsa.PrivateKey
	parsed, err = jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPrivKey
	}
	mw.privKey[signerName] = parsed
	return nil
}

func (mw *GinJWTMiddleware[K]) readPublicKey(
	signerName string,
	key Key,
) error {
	var keyData []byte
	var err error
	if key.PubKeyFile == "" {
		keyData = []byte(key.Data)
	} else {
		keyData, err = os.ReadFile(key.PubKeyFile)
	}

	if err != nil {
		return ErrNoPubKeyFile
	}

	if key.IsJWK {
		return mw.readJWK(signerName, key, keyData)
	}

	if err != nil {
		return err
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPubKey
	}
	mw.pubKey[signerName] = pubKey
	mw.PubKeyBytes[signerName] = keyData
	return nil
}

func (mw *GinJWTMiddleware[K]) usingPublicKeyAlgo() bool {
	switch mw.SigningAlgorithm {
	case "RS256", "RS512", "RS384":
		return true
	}
	return false
}

// MiddlewareInit initialize jwt configs.
func (mw *GinJWTMiddleware[K]) MiddlewareInit(signers ...Signer) error {

	if mw.DefaultOptions == nil {
		mw.DefaultOptions = &Options{}
	}

	if mw.TokenLookup == "" {
		mw.TokenLookup = "header:Authorization"
	}

	if mw.SigningAlgorithm == "" {
		mw.SigningAlgorithm = "HS256"
	}

	if mw.Timeout == 0 {
		mw.Timeout = time.Hour
	}

	if mw.TimeoutFunc == nil {
		mw.TimeoutFunc = func(data interface{}) time.Duration {
			return mw.Timeout
		}
	}

	if mw.TimeFunc == nil {
		mw.TimeFunc = time.Now
	}

	mw.TokenHeadName = strings.TrimSpace(mw.TokenHeadName)
	if len(mw.TokenHeadName) == 0 {
		mw.TokenHeadName = "Bearer"
	}

	if mw.Authorizator == nil {
		mw.Authorizator = func(data interface{}, c *gin.Context) bool {
			return true
		}
	}

	if mw.Unauthorized == nil {
		mw.Unauthorized = func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		}
	}

	if mw.LoginResponse == nil {
		mw.LoginResponse = func(c *gin.Context, code int, token string, expire time.Time) (*AuthResponse, error) {
			return &AuthResponse{
				Code:   http.StatusOK,
				Token:  token,
				Expire: expire.Format(time.RFC3339),
			}, nil
		}
	}

	if mw.LogoutResponse == nil {
		mw.LogoutResponse = func(c *gin.Context, code int) (*AuthResponse, error) {
			return &AuthResponse{
				Code: http.StatusOK,
			}, nil

		}
	}

	if mw.RefreshResponse == nil {
		mw.RefreshResponse = func(c *gin.Context, code int, token string, expire time.Time) (*AuthResponse, error) {

			return &AuthResponse{
				Code:   http.StatusOK,
				Token:  token,
				Expire: expire.Format(time.RFC3339),
			}, nil
		}
	}

	if mw.IdentityKey == "" {
		mw.IdentityKey = IdentityKey
	}

	if mw.IdentityHandler == nil {
		mw.IdentityHandler = func(c *gin.Context) interface{} {
			claims := ExtractClaims(c)
			return claims[mw.IdentityKey]
		}
	}

	if mw.HTTPStatusMessageFunc == nil {
		mw.HTTPStatusMessageFunc = func(e error, c *gin.Context) string {
			return e.Error()
		}
	}

	if mw.Realm == "" {
		mw.Realm = "gin jwt"
	}

	if mw.CookieMaxAge == 0 {
		mw.CookieMaxAge = mw.Timeout
	}

	if mw.CookieName == "" {
		mw.CookieName = "jwt"
	}

	if mw.ExpField == "" {
		mw.ExpField = "exp"
	}

	// bypass other key settings if KeyFunc is set
	if mw.KeyFunc != nil {
		return nil
	}

	if mw.usingPublicKeyAlgo() && mw.Keys == nil {
		mw.Keys = make(map[string]*Key)
	}

	if mw.usingPublicKeyAlgo() && mw.Signers == nil {
		mw.Signers = make(map[string]jose.Signer)
	}

	if mw.usingPublicKeyAlgo() && mw.VerifierKeys == nil {
		mw.VerifierKeys = make(map[string]interface{})
	}

	if mw.usingPublicKeyAlgo() {
		mw.pubKey = make(map[string]*rsa.PublicKey)
		mw.privKey = make(map[string]*rsa.PrivateKey)
		mw.PubKeyBytes = make(map[string][]byte)
		mw.PrivKeyBytes = make(map[string][]byte)

		for _, signer := range signers {
			if len(signer.Keys) == 0 {
				continue
			}
			for _, key := range signer.Keys {

				err := mw.readKey(signer.Name, key)
				if err != nil {
					return err
				}

			}
		}

		if defaultSigner := mw.DefaultSigner; defaultSigner != nil {

			for _, key := range defaultSigner.Keys {
				err := mw.readKey(defaultSigner.Name, key)
				if err != nil {
					return err
				}

			}
		}

		return nil
	}

	if mw.Key == nil {
		return ErrMissingSecretKey
	}

	return nil
}

func (mw *GinJWTMiddleware[K]) readJWK(
	signerName string,
	key Key,
	keyData []byte,
) error {
	jwkKey := &jose.JSONWebKey{}
	err := jwkKey.UnmarshalJSON(keyData)
	if err != nil {
		return err
	}
	if jwkKey.IsPublic() {
		if _, ok := mw.VerifierKeys[signerName]; ok {
			return fmt.Errorf("multiple public keys for environment %s", signerName)
		}

		mw.VerifierKeys[signerName] = jwkKey

	} else {
		if _, ok := mw.Signers[signerName]; ok {
			return fmt.Errorf("multiple private keys for environment %s", signerName)
		}
		newSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwkKey.Algorithm), Key: jwkKey.Key}, nil)
		if err != nil {
			return err
		}
		mw.Signers[signerName] = newSigner
	}

	mw.Keys[signerName] = &key

	return nil
}

// MiddlewareFunc makes GinJWTMiddleware implement the Middleware interface.
func (mw *GinJWTMiddleware[K]) MiddlewareFunc(opts ...*Options) gin.HandlerFunc {

	if len(opts) > 0 {
		mw.DefaultOptions = opts[0]
	}

	return func(c *gin.Context) {
		mw.middlewareImpl(c, mw.DefaultOptions)
	}
}

func (mw *GinJWTMiddleware[K]) middlewareImpl(c *gin.Context, opts *Options) {
	claims, err := mw.GetClaimsFromJWT(c, opts)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
		return
	}

	switch v := claims[mw.ExpField].(type) {
	case nil:
		mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrMissingExpField, c))
		return
	case float64:
		if int64(v) < mw.TimeFunc().Unix() {
			mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrExpiredToken, c))
			return
		}
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrWrongFormatOfExp, c))
			return
		}
		if n < mw.TimeFunc().Unix() {
			mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrExpiredToken, c))
			return
		}
	default:
		mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrWrongFormatOfExp, c))
		return
	}

	c.Set("JWT_PAYLOAD", claims)
	identity := mw.IdentityHandler(c)

	if identity != nil {
		c.Set(mw.IdentityKey, identity)
	}

	if !mw.Authorizator(identity, c) {
		mw.unauthorized(c, http.StatusForbidden, mw.HTTPStatusMessageFunc(ErrForbidden, c))
		return
	}

	c.Next()
}

// GetClaimsFromJWT get claims from JWT token
func (mw *GinJWTMiddleware[K]) GetClaimsFromJWT(c *gin.Context, opts *Options) (jwt.MapClaims, error) {
	token, err := mw.ParseToken(c, opts)
	if err != nil {
		return nil, err
	}

	if mw.SendAuthorization {
		if v, ok := c.Get("JWT_TOKEN"); ok {
			c.Header("Authorization", mw.TokenHeadName+" "+v.(string))
		}
	}

	claims := jwt.MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims, nil
}

func ErrHook(c *gin.Context, e error) (int, interface{}) {

	errcode, errpl := 500, e.Error()
	if _, ok := e.(tonic.BindError); ok {
		errcode, errpl = 401, ErrMissingLoginValues.Error()
	} else {
		switch {
		case jujuErr.Is(e, jujuErr.BadRequest) || jujuErr.Is(e, jujuErr.NotValid) || jujuErr.Is(e, jujuErr.AlreadyExists) || jujuErr.Is(e, jujuErr.NotSupported) || jujuErr.Is(e, jujuErr.NotAssigned) || jujuErr.Is(e, jujuErr.NotProvisioned):
			errcode, errpl = 400, e.Error()
		case jujuErr.Is(e, jujuErr.Forbidden):
			errcode, errpl = 403, e.Error()
		case jujuErr.Is(e, jujuErr.MethodNotAllowed):
			errcode, errpl = 405, e.Error()
		case jujuErr.Is(e, jujuErr.NotFound) || jujuErr.Is(e, jujuErr.UserNotFound):
			errcode, errpl = 404, e.Error()
		case jujuErr.Is(e, jujuErr.Unauthorized):
			errcode, errpl = 401, e.Error()
		case jujuErr.Is(e, jujuErr.NotImplemented):
			errcode, errpl = 501, e.Error()
		}
	}

	return errcode, &AuthResponse{
		Message: errpl,
		Code:    errcode,
	}
}

// LoginHandler can be used by clients to get a jwt token.
// Payload needs to be json in the form of {"username": "USERNAME", "password": "PASSWORD"}.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *GinJWTMiddleware[K]) LoginHandler(c *gin.Context, req K) (*AuthResponse, error) {

	if mw.Authenticator == nil {
		return nil, errors.New(ErrMissingAuthenticatorFunc.Error())
	}

	data, err := mw.Authenticator(c, req)
	if err != nil {
		return nil, jujuErr.NewUnauthorized(nil, err.Error())
	}

	// Create the token
	generated, err := mw.CreateToken(data, mw.DefaultOptions)
	if err != nil {
		return nil, jujuErr.NewUnauthorized(nil, err.Error())
	}

	mw.SetCookie(c, generated.Token)
	c.Header("token", generated.Token)
	c.Header("expire", generated.Expire.Format(time.RFC3339))

	return mw.LoginResponse(c, http.StatusOK, generated.Token, generated.Expire)
}

func (mw *GinJWTMiddleware[K]) CreateToken(data interface{}, opts ...*Options) (*GeneratedToken, error) {
	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(data) {
			claims[key] = value
		}
	}

	var options *Options
	if len(opts) > 0 {
		options = opts[0]
	} else {
		options = mw.DefaultOptions
	}

	expire := mw.TimeFunc().Add(mw.TimeoutFunc(claims))
	claims[mw.ExpField] = expire.Unix()
	claims["orig_iat"] = mw.TimeFunc().Unix()
	tokenString, err := mw.signedString(token, options)
	if err != nil {
		return nil, err
	}

	return &GeneratedToken{
		Token:  tokenString,
		Expire: expire,
	}, err
}

type AuthError struct {
	Message string `json:"message"`
}

// LogoutHandler can be used by clients to remove the jwt cookie (if set)
func (mw *GinJWTMiddleware[K]) LogoutHandler(c *gin.Context) (*AuthResponse, error) {
	// delete auth cookie
	if mw.SendCookie {
		if mw.CookieSameSite != 0 {
			c.SetSameSite(mw.CookieSameSite)
		}

		c.SetCookie(
			mw.CookieName,
			"",
			-1,
			"/",
			mw.CookieDomain,
			mw.SecureCookie,
			mw.CookieHTTPOnly,
		)
	}

	return mw.LogoutResponse(c, 200)
}

func (mw *GinJWTMiddleware[K]) signedString(token *jwt.Token, opts *Options) (string, error) {

	signerName := opts.SignerName
	if signerName == "" && !mw.usingPublicKeyAlgo() {
		return token.SignedString(mw.Key)
	}

	if signerName == "" && mw.DefaultSigner != nil {
		signerName = mw.DefaultSigner.Name
		opts = &Options{
			SignerName: signerName,
		}
	}

	key, ok := mw.Keys[signerName]
	if !ok {
		return "", fmt.Errorf("key for signer %s not found", signerName)
	}

	if key.IsJWK {
		return mw.signJWK(token, opts)
	}

	return token.SignedString(mw.privKey[signerName])
}

func (mw *GinJWTMiddleware[K]) signJWK(token *jwt.Token, opts *Options) (string, error) {

	if token == nil || token.Claims == nil {
		return "", fmt.Errorf("payload is empty")
	}

	payload, err := json.Marshal(token.Claims.(jwt.MapClaims))
	if err != nil {
		return "", err
	}

	if payload == nil {
		return "", fmt.Errorf("payload is empty")
	}
	signer, ok := mw.Signers[opts.SignerName]
	if !ok {
		return "", fmt.Errorf("signer %s not found", opts.SignerName)
	}
	signedPayload, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	serializedPayload, err := signedPayload.CompactSerialize()
	if err != nil {
		return "", err
	}
	return serializedPayload, nil
}

// RefreshHandler can be used to refresh a token. The token still needs to be valid on refresh.
// Shall be put under an endpoint that is using the GinJWTMiddleware.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *GinJWTMiddleware[K]) RefreshHandler(c *gin.Context) (*AuthResponse, error) {
	tokenString, expire, err := mw.RefreshToken(c, mw.DefaultOptions)
	if err != nil {
		return nil, jujuErr.NewUnauthorized(err, err.Error())
	}

	c.Header("token", tokenString)
	c.Header("expire", expire.Format(time.RFC3339))

	return mw.RefreshResponse(c, http.StatusOK, tokenString, expire)
}

func (mw *GinJWTMiddleware[K]) RefreshIfRequired(token string, opts *Options) (*GeneratedToken, error) {
	claims, expired, err := mw.CheckIfExpired(token, opts)
	if err != nil {
		return &GeneratedToken{
			Token:  "",
			Expire: time.Now(),
		}, err
	}

	if !expired {
		sec, dec := math.Modf(claims["exp"].(float64))
		return &GeneratedToken{
			Token: token,
			Expire: time.Unix(
				int64(sec),
				int64(dec*(1e9)),
			),
		}, nil
	}
	// Create the token
	newToken := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	newClaims := newToken.Claims.(jwt.MapClaims)

	for key := range claims {
		newClaims[key] = claims[key]
	}

	expire := mw.TimeFunc().Add(mw.TimeoutFunc(claims))
	newClaims[mw.ExpField] = expire.Unix()
	newClaims["orig_iat"] = mw.TimeFunc().Unix()
	tokenString, err := mw.signedString(newToken, opts)
	if err != nil {
		return &GeneratedToken{
			Token:  "",
			Expire: time.Now(),
		}, err
	}

	return &GeneratedToken{
		Token:  tokenString,
		Expire: expire,
	}, nil
}

// RefreshToken refresh token and check if token is expired
func (mw *GinJWTMiddleware[K]) RefreshToken(c *gin.Context, opts ...*Options) (string, time.Time, error) {

	var options *Options
	if len(opts) > 0 {
		options = opts[0]
	} else {
		options = mw.DefaultOptions
	}

	claims, err := mw.CheckIfTokenExpire(c, options)
	if err != nil {
		return "", time.Now(), err
	}

	// Create the token
	newToken := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	newClaims := newToken.Claims.(jwt.MapClaims)

	for key := range claims {
		newClaims[key] = claims[key]
	}

	expire := mw.TimeFunc().Add(mw.TimeoutFunc(claims))
	newClaims[mw.ExpField] = expire.Unix()
	newClaims["orig_iat"] = mw.TimeFunc().Unix()

	tokenString, err := mw.signedString(newToken, options)
	if err != nil {
		return "", time.Now(), err
	}

	mw.SetCookie(c, tokenString)

	return tokenString, expire, nil
}

// CheckIfTokenExpire check if token expire
func (mw *GinJWTMiddleware[K]) CheckIfTokenExpire(c *gin.Context, opts *Options) (jwt.MapClaims, error) {
	token, err := mw.ParseToken(c, opts)
	if err != nil {
		// If we receive an error, and the error is anything other than a single
		// ValidationErrorExpired, we want to return the error.
		// If the error is just ValidationErrorExpired, we want to continue, as we can still
		// refresh the token if it's within the MaxRefresh time.
		// (see https://github.com/appleboy/gin-jwt/issues/176)
		validationErr, ok := err.(*jwt.ValidationError)
		if !ok || validationErr.Errors != jwt.ValidationErrorExpired {
			return nil, err
		}
	}

	claims := token.Claims.(jwt.MapClaims)

	origIat := int64(claims["orig_iat"].(float64))

	if origIat < mw.TimeFunc().Add(-mw.MaxRefresh).Unix() {
		return nil, ErrExpiredToken
	}

	return claims, nil
}

func (mw *GinJWTMiddleware[K]) CheckIfExpired(tokenString string, opts *Options) (jwt.MapClaims, bool, error) {
	token, err := mw.ParseTokenFromString(tokenString, opts)

	expired := false
	if err != nil {
		// If we receive an error, and the error is anything other than a single
		// ValidationErrorExpired, we want to return the error.
		// If the error is just ValidationErrorExpired, we want to continue, as we can still
		// refresh the token if it's within the MaxRefresh time.
		// (see https://github.com/appleboy/gin-jwt/issues/176)
		validationErr, ok := err.(*jwt.ValidationError)
		if !ok || validationErr.Errors != jwt.ValidationErrorExpired {
			return nil, expired, err
		}

		expired = true
	}

	claims := token.Claims.(jwt.MapClaims)

	origIat := int64(claims["orig_iat"].(float64))

	if origIat < mw.TimeFunc().Add(-mw.MaxRefresh).Unix() {
		return nil, expired, ErrExpiredToken
	}

	return claims, expired, nil
}

// TokenGenerator method that clients can use to get a jwt token.
func (mw *GinJWTMiddleware[K]) TokenGenerator(data interface{}, opts *Options) (string, time.Time, error) {
	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(data) {
			claims[key] = value
		}
	}

	expire := mw.TimeFunc().Add(mw.TimeoutFunc(claims))
	claims[mw.ExpField] = expire.Unix()
	claims["orig_iat"] = mw.TimeFunc().Unix()
	tokenString, err := mw.signedString(token, opts)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expire, nil
}

func (mw *GinJWTMiddleware[K]) jwtFromHeader(c *gin.Context, key string) (string, error) {
	authHeader := c.Request.Header.Get(key)

	if authHeader == "" {
		return "", ErrEmptyAuthHeader
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == mw.TokenHeadName) {
		return "", ErrInvalidAuthHeader
	}

	return parts[1], nil
}

func (mw *GinJWTMiddleware[K]) jwtFromQuery(c *gin.Context, key string) (string, error) {
	token := c.Query(key)

	if token == "" {
		return "", ErrEmptyQueryToken
	}

	return token, nil
}

func (mw *GinJWTMiddleware[K]) jwtFromCookie(c *gin.Context, key string) (string, error) {
	cookie, _ := c.Cookie(key)

	if cookie == "" {
		return "", ErrEmptyCookieToken
	}

	return cookie, nil
}

func (mw *GinJWTMiddleware[K]) jwtFromParam(c *gin.Context, key string) (string, error) {
	token := c.Param(key)

	if token == "" {
		return "", ErrEmptyParamToken
	}

	return token, nil
}

func (mw *GinJWTMiddleware[K]) jwtFromForm(c *gin.Context, key string) (string, error) {
	token := c.PostForm(key)

	if token == "" {
		return "", ErrEmptyParamToken
	}

	return token, nil
}

// ParseToken parse jwt token from gin context
func (mw *GinJWTMiddleware[K]) ParseToken(c *gin.Context, opts *Options) (*jwt.Token, error) {
	var token string
	var err error

	methods := strings.Split(mw.TokenLookup, ",")
	for _, method := range methods {
		if len(token) > 0 {
			break
		}
		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case "header":
			token, err = mw.jwtFromHeader(c, v)
		case "query":
			token, err = mw.jwtFromQuery(c, v)
		case "cookie":
			token, err = mw.jwtFromCookie(c, v)
		case "param":
			token, err = mw.jwtFromParam(c, v)
		case "form":
			token, err = mw.jwtFromForm(c, v)
		}
	}

	if err != nil {
		return nil, err
	}

	if opts := mw.checkIfJWK(opts); opts != nil {
		jwtToken, verifiedToken, err := mw.parseJWK(token, opts)

		if err != nil {
			c.Set("JWT_TOKEN", verifiedToken)
		}

		return jwtToken, err
	}

	if mw.KeyFunc != nil {
		return jwt.Parse(token, mw.KeyFunc, mw.ParseOptions...)
	}

	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		if mw.usingPublicKeyAlgo() {
			return mw.pubKey[opts.SignerName], nil
		}

		// save token string if valid
		c.Set("JWT_TOKEN", token)

		return mw.Key, nil
	}, mw.ParseOptions...)
}

func (mw *GinJWTMiddleware[K]) parseJWK(token string, opts *Options) (*jwt.Token, string, error) {
	verifiedToken, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(mw.SigningAlgorithm)})
	if err != nil {
		return nil, "", err
	}
	verifier, ok := mw.VerifierKeys[opts.SignerName]
	if !ok {
		return nil, "", fmt.Errorf("verifier %s not found", opts.SignerName)
	}
	payload, err := verifiedToken.Verify(verifier)
	if err != nil {
		return nil, "", fmt.Errorf("jwt verification failed: %w", err)
	}

	jwtToken := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	claims := jwtToken.Claims.(jwt.MapClaims)

	err = json.Unmarshal(payload, &claims)
	if err != nil {
		return nil, "", err
	}

	verified := string(payload)

	return jwtToken, verified, err
}

// ParseToken parse jwt token from string
func (mw *GinJWTMiddleware[K]) ParseTokenFromString(token string, opts *Options) (*jwt.Token, error) {

	if mw.KeyFunc != nil {
		return jwt.Parse(token, mw.KeyFunc, mw.ParseOptions...)
	}
	if opts := mw.checkIfJWK(opts); opts != nil {
		jwtToken, _, err := mw.parseJWK(token, opts)

		return jwtToken, err
	}

	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}

		if mw.usingPublicKeyAlgo() {
			return mw.pubKey[opts.SignerName], nil
		}

		return mw.Key, nil
	}, mw.ParseOptions...)
}

func (mw *GinJWTMiddleware[K]) checkIfJWK(opts *Options) *Options {
	signerName := opts.SignerName
	if signerName == "" && mw.DefaultSigner == nil {
		return nil
	}

	if signerName == "" {
		signerName = mw.DefaultSigner.Name
	}

	key, ok := mw.Keys[signerName]
	if !ok {
		return nil
	}

	if key.IsJWK {
		return &Options{
			SignerName: signerName,
		}
	}

	return nil

}

func (mw *GinJWTMiddleware[K]) unauthorized(c *gin.Context, code int, message string) {
	c.Header("WWW-Authenticate", "JWT realm="+mw.Realm)
	if !mw.DisabledAbort {
		c.Abort()
	}

	mw.Unauthorized(c, code, message)
}

// ExtractClaims help to extract the JWT claims
func ExtractClaims(c *gin.Context) jwt.MapClaims {
	claims, exists := c.Get("JWT_PAYLOAD")
	if !exists {
		return make(jwt.MapClaims)
	}

	return claims.(jwt.MapClaims)
}

// ExtractClaimsFromToken help to extract the JWT claims from token
func ExtractClaimsFromToken(token *jwt.Token) jwt.MapClaims {
	if token == nil {
		return make(jwt.MapClaims)
	}

	claims := jwt.MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims
}

// GetToken help to get the JWT token string
func GetToken(c *gin.Context) string {
	token, exists := c.Get("JWT_TOKEN")
	if !exists {
		return ""
	}

	return token.(string)
}

// SetCookie help to set the token in the cookie
func (mw *GinJWTMiddleware[K]) SetCookie(c *gin.Context, token string) {
	// set cookie
	if mw.SendCookie {
		expireCookie := mw.TimeFunc().Add(mw.CookieMaxAge)
		maxage := int(expireCookie.Unix() - mw.TimeFunc().Unix())

		if mw.CookieSameSite != 0 {
			c.SetSameSite(mw.CookieSameSite)
		}

		c.SetCookie(
			mw.CookieName,
			token,
			maxage,
			"/",
			mw.CookieDomain,
			mw.SecureCookie,
			mw.CookieHTTPOnly,
		)
	}
}
