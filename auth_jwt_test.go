package jwt

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/appleboy/gofight/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jose-util/generator"
	"github.com/golang-jwt/jwt/v4"
	"github.com/loopfz/gadgeto/tonic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// Login form structure.
type Login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

var (
	key                  = []byte("secret key")
	defaultAuthenticator = func(c *gin.Context, user *Login) (interface{}, error) {
		var loginVals Login
		userID := loginVals.Username
		password := loginVals.Password

		if userID == "admin" && password == "admin" {
			return userID, nil
		}

		return userID, ErrFailedAuthentication
	}
)

func makeTokenString(SigningAlgorithm string, username string) string {
	if SigningAlgorithm == "" {
		SigningAlgorithm = "HS256"
	}

	token := jwt.New(jwt.GetSigningMethod(SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = username
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["orig_iat"] = time.Now().Unix()
	var tokenString string
	if SigningAlgorithm == "RS256" {
		keyData, _ := os.ReadFile("testdata/jwtRS256.key")
		signKey, _ := jwt.ParseRSAPrivateKeyFromPEM(keyData)
		tokenString, _ = token.SignedString(signKey)
	} else {
		tokenString, _ = token.SignedString(key)
	}

	return tokenString
}

func keyFunc(token *jwt.Token) (interface{}, error) {
	cert, err := os.ReadFile("testdata/jwtRS256.key.pub")
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPublicKeyFromPEM(cert)
}

func TestMissingKey(t *testing.T) {
	_, err := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
	})

	assert.Error(t, err)
	assert.Equal(t, ErrMissingSecretKey, err)
}

func TestMissingPrivKey(t *testing.T) {
	_, err := New(&GinJWTMiddleware[*Login]{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
	}, Signer{
		Name: "test",
		Keys: []Key{
			{
				PrivKeyFile: "nonexisting",
			},
		},
	})

	assert.Error(t, err)
	assert.Equal(t, ErrNoPrivKeyFile, err)
}

func TestMissingPubKey(t *testing.T) {
	_, err := New(&GinJWTMiddleware[*Login]{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
	}, Signer{
		Name: "test",
		Keys: []Key{
			{
				PrivKeyFile: "testdata/jwtRS256.key",
				PubKeyFile:  "nonexisting",
			},
		},
	})

	assert.Error(t, err)
	assert.Equal(t, ErrNoPubKeyFile, err)
}

func TestInvalidPrivKey(t *testing.T) {
	_, err := New(&GinJWTMiddleware[*Login]{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
	}, Signer{
		Name: "test",
		Keys: []Key{
			{
				PrivKeyFile: "testdata/invalidprivkey.key",
				PubKeyFile:  "testdata/jwtRS256.key.pub",
			},
		},
	})

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPrivKey, err)
}

func TestInvalidPrivKeyBytes(t *testing.T) {
	_, err := New(&GinJWTMiddleware[*Login]{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
	}, Signer{
		Name: "test",
		Keys: []Key{
			{
				Data:       "Invalid_Private_Key",
				PubKeyFile: "testdata/jwtRS256.key.pub",
			},
		},
	})

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPrivKey, err)
}

func TestInvalidPubKey(t *testing.T) {
	_, err := New(&GinJWTMiddleware[*Login]{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
	}, Signer{
		Name: "test",
		Keys: []Key{
			{
				PrivKeyFile: "testdata/jwtRS256.key",
				PubKeyFile:  "testdata/invalidpubkey.key",
			},
		},
	})

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPubKey, err)
}

func TestInvalidPubKeyBytes(t *testing.T) {
	_, err := New(&GinJWTMiddleware[*Login]{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
	}, Signer{
		Name: "test",
		Keys: []Key{
			{
				PrivKeyFile: "testdata/jwtRS256.key",
				Data:        "Invalid_Private_Key",
			},
		},
	})

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPubKey, err)
}

func TestMissingTimeOut(t *testing.T) {
	authMiddleware, err := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		Key:           key,
		Authenticator: defaultAuthenticator,
	})

	assert.NoError(t, err)
	assert.Equal(t, time.Hour, authMiddleware.Timeout)
}

func TestMissingTokenLookup(t *testing.T) {
	authMiddleware, err := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		Key:           key,
		Authenticator: defaultAuthenticator,
	})

	assert.NoError(t, err)
	assert.Equal(t, "header:Authorization", authMiddleware.TokenLookup)
}

func helloHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"text":  "Hello World.",
		"token": GetToken(c),
	})
}

func ginHandler(auth *GinJWTMiddleware[*Login]) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	tonic.SetErrorHook(ErrHook)
	r.POST("/login", tonic.Handler(auth.LoginHandler, 200))
	r.POST("/logout", tonic.Handler(auth.LogoutHandler, 200))
	// test token in path
	r.GET("/g/:token/refresh_token", tonic.Handler(auth.RefreshHandler, 200))

	group := r.Group("/auth")
	// Refresh time can be longer than token timeout
	group.GET("/refresh_token", tonic.Handler(auth.RefreshHandler, 200))
	group.Use(auth.MiddlewareFunc())
	{
		group.GET("/hello", helloHandler)
	}

	return r
}

func TestMissingAuthenticatorForLoginHandler(t *testing.T) {
	authMiddleware, err := New(&GinJWTMiddleware[*Login]{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
	})

	assert.NoError(t, err)

	handler := ginHandler(authMiddleware)
	r := gofight.New()

	r.POST("/login").
		SetJSON(gofight.D{
			"username": "admin",
			"password": "admin",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			message := gjson.Get(r.Body.String(), "message")

			assert.Equal(t, ErrMissingAuthenticatorFunc.Error(), message.String())
			assert.Equal(t, http.StatusInternalServerError, r.Code)
		})
}

func TestLoginHandler(t *testing.T) {
	// the middleware to test
	cookieName := "jwt"
	cookieDomain := "example.com"
	authMiddleware, err := New(&GinJWTMiddleware[*Login]{
		Realm: "test zone",
		Key:   key,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			// Set custom claim, to be checked in Authorizator method
			return jwt.MapClaims{"testkey": "testval", "exp": 0}
		},
		Authenticator: func(c *gin.Context, user *Login) (interface{}, error) {

			if user.Username == "admin" && user.Password == "admin" {
				return user.Username, nil
			}
			return "", ErrFailedAuthentication
		},
		Validator: func(user interface{}, c *gin.Context) bool {
			return true
		},
		LoginResponse: func(c *gin.Context, code int, token string, t time.Time) (*AuthResponse, error) {
			cookie, err := c.Cookie("jwt")
			if err != nil {
				log.Println(err)
			}

			return &AuthResponse{
				Code:    http.StatusOK,
				Token:   token,
				Expire:  t.Format(time.RFC3339),
				Message: "login successfully",
				Cookie:  cookie,
			}, nil
		},
		SendCookie:   true,
		CookieName:   cookieName,
		CookieDomain: cookieDomain,
		TimeFunc:     func() time.Time { return time.Now().Add(time.Duration(5) * time.Minute) },
	})

	assert.NoError(t, err)

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.POST("/login").
		SetJSON(gofight.D{
			"username": "admin",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			message := gjson.Get(r.Body.String(), "message")

			assert.Equal(t, ErrMissingLoginValues.Error(), message.String())
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			//nolint:staticcheck
			assert.Equal(t, "application/json; charset=utf-8", r.HeaderMap.Get("Content-Type"))
		})

	r.POST("/login").
		SetJSON(gofight.D{
			"username": "admin",
			"password": "test",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			message := gjson.Get(r.Body.String(), "message")
			assert.Equal(t, ErrFailedAuthentication.Error(), message.String())
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.POST("/login").
		SetJSON(gofight.D{
			"username": "admin",
			"password": "admin",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			message := gjson.Get(r.Body.String(), "message")
			assert.Equal(t, "login successfully", message.String())
			assert.Equal(t, http.StatusOK, r.Code)
			//nolint:staticcheck
			assert.True(t, strings.HasPrefix(r.HeaderMap.Get("Set-Cookie"), "jwt="))
			//nolint:staticcheck
			assert.True(t, strings.HasSuffix(r.HeaderMap.Get("Set-Cookie"), "; Path=/; Domain=example.com; Max-Age=3600"))
		})
}

func TestParseToken(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Test 1234",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS384", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestParseTokenRS256(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		DefaultOptions: &Options{
			SignerName: "test",
		},
		Realm:            "test zone",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		SigningAlgorithm: "RS256",
		Authenticator:    defaultAuthenticator,
	}, Signer{
		Name: "test",
		Keys: []Key{
			{
				PrivKeyFile: "testdata/jwtRS256.key",
				PubKeyFile:  "testdata/jwtRS256.key.pub",
			},
		},
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Test 1234",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS384", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("RS256", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestParseTokenKeyFunc(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		KeyFunc:       keyFunc,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
		// make sure it skips these settings
		Key:              []byte(""),
		SigningAlgorithm: "RS256",
	}, Signer{
		Name: "test",
		Keys: []Key{
			{
				PrivKeyFile: "",
				PubKeyFile:  "",
			},
		},
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Test 1234",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS384", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("RS256", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestRefreshHandlerRS256(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		DefaultOptions: &Options{
			SignerName: "test",
		},
		Realm:            "test zone",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		SigningAlgorithm: "RS256",
		SendCookie:       true,
		CookieName:       "jwt",
		Authenticator:    defaultAuthenticator,
		RefreshResponse: func(c *gin.Context, code int, token string, t time.Time) (*AuthResponse, error) {
			cookie, err := c.Cookie("jwt")
			if err != nil {
				return nil, err
			}

			return &AuthResponse{
				Code:    http.StatusOK,
				Token:   token,
				Expire:  t.Format(time.RFC3339),
				Message: "refresh successfully",
				Cookie:  cookie,
			}, nil
		},
	}, Signer{
		Name: "test",
		Keys: []Key{
			{
				PrivKeyFile: "testdata/jwtRS256.key",
				PubKeyFile:  "testdata/jwtRS256.key.pub",
			},
		},
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "Test 1234",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})
	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("RS256", "admin"),
		}).
		SetCookie(gofight.H{
			"jwt": makeTokenString("RS256", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			message := gjson.Get(r.Body.String(), "message")
			cookie := gjson.Get(r.Body.String(), "cookie")
			assert.Equal(t, "refresh successfully", message.String())
			assert.Equal(t, http.StatusOK, r.Code)
			assert.Equal(t, makeTokenString("RS256", "admin"), cookie.String())
		})
}

func TestRefreshHandler(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "Test 1234",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestExpiredTokenWithinMaxRefreshOnRefreshHandler(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    2 * time.Hour,
		Authenticator: defaultAuthenticator,
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = "admin"
	claims["exp"] = time.Now().Add(-time.Minute).Unix()
	claims["orig_iat"] = time.Now().Add(-time.Hour).Unix()
	tokenString, _ := token.SignedString(key)

	// We should be able to refresh a token that has expired but is within the MaxRefresh time
	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + tokenString,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestExpiredTokenOnRefreshHandler(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = "admin"
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["orig_iat"] = 0
	tokenString, _ := token.SignedString(key)

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + tokenString,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})
}

func TestValidator(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
		Validator: func(data interface{}, c *gin.Context) bool {
			mapped := data.(jwt.MapClaims)
			identity := mapped["identity"].(string)

			return identity == "admin"
		},
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", "test"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusForbidden, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestParseTokenWithJsonNumber(t *testing.T) {
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.String(code, message)
		},
		ParseOptions: []jwt.ParserOption{jwt.WithJSONNumber()},
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestClaimsDuringAuthorization(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(jwt.MapClaims); ok {
				return v
			}

			if reflect.TypeOf(data).String() != "string" {
				return jwt.MapClaims{}
			}

			var testkey string
			switch data.(string) {
			case "admin":
				testkey = "1234"
			case "test":
				testkey = "5678"
			case "Guest":
				testkey = ""
			}
			// Set custom claim, to be checked in Authorizator method
			return jwt.MapClaims{"identity": data.(string), "testkey": testkey, "exp": 0}
		},
		Authenticator: func(c *gin.Context, user *Login) (interface{}, error) {

			if user.Username == "admin" && user.Password == "admin" {
				return user.Username, nil
			}

			if user.Username == "test" && user.Password == "test" {
				return user.Username, nil
			}

			return "Guest", ErrFailedAuthentication
		},
		Validator: func(user interface{}, c *gin.Context) bool {
			jwtClaims := ExtractClaims(c)

			if jwtClaims["identity"] == "administrator" {
				return true
			}

			if jwtClaims["testkey"] == "1234" && jwtClaims["identity"] == "admin" {
				return true
			}

			if jwtClaims["testkey"] == "5678" && jwtClaims["identity"] == "test" {
				return true
			}

			return false
		},
	})

	r := gofight.New()
	handler := ginHandler(authMiddleware)

	userToken, _, _ := authMiddleware.TokenGenerator(jwt.MapClaims{
		"identity": "administrator",
	}, &Options{})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})

	r.POST("/login").
		SetJSON(gofight.D{
			"username": "admin",
			"password": "admin",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			token := gjson.Get(r.Body.String(), "token")
			userToken = token.String()
			assert.Equal(t, http.StatusOK, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})

	r.POST("/login").
		SetJSON(gofight.D{
			"username": "test",
			"password": "test",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			token := gjson.Get(r.Body.String(), "token")
			userToken = token.String()
			assert.Equal(t, http.StatusOK, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func ConvertClaims(claims jwt.MapClaims) map[string]interface{} {
	return map[string]interface{}{}
}

func TestEmptyClaims(t *testing.T) {
	var jwtClaims jwt.MapClaims

	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(c *gin.Context, user *Login) (interface{}, error) {
			var loginVals Login
			userID := loginVals.Username
			password := loginVals.Password

			if userID == "admin" && password == "admin" {
				return "", nil
			}

			if userID == "test" && password == "test" {
				return "Administrator", nil
			}

			return userID, ErrFailedAuthentication
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			assert.Empty(t, ExtractClaims(c))
			assert.Empty(t, ConvertClaims(ExtractClaims(c)))
			c.String(code, message)
		},
	})

	r := gofight.New()
	handler := ginHandler(authMiddleware)

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer 1234",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	assert.Empty(t, jwtClaims)
}

func TestUnauthorized(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.String(code, message)
		},
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer 1234",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})
}

func TestTokenExpire(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    -time.Second,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.String(code, message)
		},
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	userToken, _, _ := authMiddleware.TokenGenerator(jwt.MapClaims{
		"identity": "admin",
	}, &Options{})

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})
}

func TestTokenFromQueryString(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.String(code, message)
		},
		TokenLookup: "query:token",
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	userToken, _, _ := authMiddleware.TokenGenerator(jwt.MapClaims{
		"identity": "admin",
	}, &Options{})

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/refresh_token?token="+userToken).
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestTokenFromParamPath(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.String(code, message)
		},
		TokenLookup: "param:token",
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	userToken, _, _ := authMiddleware.TokenGenerator(jwt.MapClaims{
		"identity": "admin",
	}, &Options{})

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/g/"+userToken+"/refresh_token").
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestTokenFromCookieString(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.String(code, message)
		},
		TokenLookup: "cookie:token",
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	userToken, _, _ := authMiddleware.TokenGenerator(jwt.MapClaims{
		"identity": "admin",
	}, &Options{})

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			token := gjson.Get(r.Body.String(), "token")
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			assert.Equal(t, "", token.String())
		})

	r.GET("/auth/refresh_token").
		SetCookie(gofight.H{
			"token": userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})

	r.GET("/auth/hello").
		SetCookie(gofight.H{
			"token": userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			token := gjson.Get(r.Body.String(), "token")
			assert.Equal(t, http.StatusOK, r.Code)
			assert.Equal(t, userToken, token.String())
		})
}

func TestDefineTokenHeadName(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		TokenHeadName: "JWTTOKEN       ",
		Authenticator: defaultAuthenticator,
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "JWTTOKEN " + makeTokenString("HS256", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestHTTPStatusMessageFunc(t *testing.T) {
	successError := errors.New("Successful test error")
	failedError := errors.New("Failed test error")
	successMessage := "Overwrite error message."

	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,

		HTTPStatusMessageFunc: func(e error, c *gin.Context) string {
			if e == successError {
				return successMessage
			}

			return e.Error()
		},
	})

	successString := authMiddleware.HTTPStatusMessageFunc(successError, nil)
	failedString := authMiddleware.HTTPStatusMessageFunc(failedError, nil)

	assert.Equal(t, successMessage, successString)
	assert.NotEqual(t, successMessage, failedString)
}

func TestSendAuthorizationBool(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:             "test zone",
		Key:               key,
		Timeout:           time.Hour,
		MaxRefresh:        time.Hour * 24,
		Authenticator:     defaultAuthenticator,
		SendAuthorization: true,
		Validator: func(data interface{}, c *gin.Context) bool {
			mapped := data.(jwt.MapClaims)
			identity := mapped["identity"].(string)
			return identity == "admin"
		},
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", "test"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusForbidden, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			//nolint:staticcheck
			token := r.HeaderMap.Get("Authorization")
			assert.Equal(t, "Bearer "+makeTokenString("HS256", "admin"), token)
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestExpiredTokenOnAuth(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:             "test zone",
		Key:               key,
		Timeout:           time.Hour,
		MaxRefresh:        time.Hour * 24,
		Authenticator:     defaultAuthenticator,
		SendAuthorization: true,
		Validator: func(data interface{}, c *gin.Context) bool {
			mapped := data.(jwt.MapClaims)
			identity := mapped["identity"].(string)
			return identity == "admin"
		},
		TimeFunc: func() time.Time {
			return time.Now().AddDate(0, 0, 1)
		},
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})
}

func TestBadTokenOnRefreshHandler(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + "BadToken",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})
}

func TestExpiredField(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = "admin"
	claims["orig_iat"] = 0
	tokenString, _ := token.SignedString(key)

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + tokenString,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			message := gjson.Get(r.Body.String(), "message")

			assert.Equal(t, ErrMissingExpField.Error(), message.String())
			assert.Equal(t, http.StatusBadRequest, r.Code)
		})

	// wrong format
	claims["exp"] = "wrongFormatForExpiryIgnoredByJwtLibrary"
	tokenString, _ = token.SignedString(key)

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + tokenString,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			message := gjson.Get(r.Body.String(), "message")

			assert.Equal(t, ErrExpiredToken.Error(), strings.ToLower(message.String()))
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})
}

func TestCheckTokenString(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		Key:           key,
		Timeout:       1 * time.Second,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.String(code, message)
		},
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(jwt.MapClaims); ok {
				return v
			}

			return nil
		},
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	userToken, _, _ := authMiddleware.TokenGenerator(jwt.MapClaims{
		"identity": "admin",
	}, &Options{})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})

	token, err := authMiddleware.ParseTokenFromString(userToken, &Options{})
	assert.NoError(t, err)
	claims := ExtractClaimsFromToken(token)
	assert.Equal(t, "admin", claims["identity"])

	time.Sleep(2 * time.Second)

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	_, err = authMiddleware.ParseTokenFromString(userToken, &Options{})
	assert.Error(t, err)
	assert.Equal(t, jwt.MapClaims{}, ExtractClaimsFromToken(nil))
}

func TestLogout(t *testing.T) {
	cookieName := "jwt"
	cookieDomain := "example.com"
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware[*Login]{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		SendCookie:    true,
		CookieName:    cookieName,
		CookieDomain:  cookieDomain,
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.POST("/logout").
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
			//nolint:staticcheck
			assert.Equal(t, fmt.Sprintf("%s=; Path=/; Domain=%s; Max-Age=0", cookieName, cookieDomain), r.HeaderMap.Get("Set-Cookie"))
		})
}

func TestSetCookie(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	mw, _ := New(&GinJWTMiddleware[*Login]{
		Realm:          "test zone",
		Key:            key,
		Timeout:        time.Hour,
		Authenticator:  defaultAuthenticator,
		SendCookie:     true,
		CookieName:     "jwt",
		CookieMaxAge:   time.Hour,
		CookieDomain:   "example.com",
		SecureCookie:   false,
		CookieHTTPOnly: true,
		TimeFunc: func() time.Time {
			return time.Now()
		},
	})

	token := makeTokenString("HS384", "admin")

	mw.SetCookie(c, token)

	cookies := w.Result().Cookies()

	assert.Len(t, cookies, 1)

	cookie := cookies[0]
	assert.Equal(t, "jwt", cookie.Name)
	assert.Equal(t, token, cookie.Value)
	assert.Equal(t, "/", cookie.Path)
	assert.Equal(t, "example.com", cookie.Domain)
	assert.Equal(t, true, cookie.HttpOnly)
}

func TestCreateToken(t *testing.T) {

	cookieName := "jwt"
	cookieDomain := "example.com"
	authMiddleware, err := New(&GinJWTMiddleware[*Login]{
		Realm: "test zone",
		Key:   key,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			// Set custom claim, to be checked in Authorizator method
			return jwt.MapClaims{"testkey": "testval", "exp": 0}
		},
		Authenticator: func(c *gin.Context, user *Login) (interface{}, error) {

			if user.Username == "admin" && user.Password == "admin" {
				return user.Username, nil
			}
			return "", ErrFailedAuthentication
		},
		Validator: func(user interface{}, c *gin.Context) bool {
			return true
		},
		LoginResponse: func(c *gin.Context, code int, token string, t time.Time) (*AuthResponse, error) {
			cookie, err := c.Cookie("jwt")
			if err != nil {
				log.Println(err)
			}

			return &AuthResponse{
				Code:    http.StatusOK,
				Token:   token,
				Expire:  t.Format(time.RFC3339),
				Message: "login successfully",
				Cookie:  cookie,
			}, nil
		},
		SendCookie:   true,
		CookieName:   cookieName,
		CookieDomain: cookieDomain,
		TimeFunc:     func() time.Time { return time.Now().Add(time.Duration(5) * time.Minute) },
	})

	if err != nil {
		t.Fatal(err)
	}

	mappedClaims := jwt.MapClaims{
		"username": "admin",
		"password": "12345",
	}

	t.Run("it creates a token given valid data", func(t *testing.T) {

		generated, err := authMiddleware.CreateToken(mappedClaims, &Options{})

		assert.Nil(t, err)
		assert.IsType(t, &GeneratedToken{}, generated)
		assert.NotNil(t, generated.Token)
		assert.IsType(t, time.Time{}, generated.Expire)

	})

	token := jwt.New(jwt.GetSigningMethod(authMiddleware.SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	if authMiddleware.PayloadFunc != nil {
		for key, value := range authMiddleware.PayloadFunc(mappedClaims) {
			claims[key] = value
		}
	}

	originalExpirationTime := time.Now().Unix()
	claims[authMiddleware.ExpField] = originalExpirationTime
	claims["orig_iat"] = authMiddleware.TimeFunc().Unix()
	tokenString, err := authMiddleware.signedString(token, &Options{})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("it refreshes a token given a valid token that has expired", func(t *testing.T) {

		generated, err := authMiddleware.RefreshIfRequired(tokenString, &Options{})

		assert.Nil(t, err)
		assert.IsType(t, &GeneratedToken{}, generated)
		assert.NotNil(t, generated.Token)
		assert.IsType(t, time.Time{}, generated.Expire)
		assert.Greater(t, generated.Expire.Unix(), originalExpirationTime)

	})

	token = jwt.New(jwt.GetSigningMethod(authMiddleware.SigningAlgorithm))
	claims = token.Claims.(jwt.MapClaims)

	if authMiddleware.PayloadFunc != nil {
		for key, value := range authMiddleware.PayloadFunc(mappedClaims) {
			claims[key] = value
		}
	}

	originalExpirationTime = time.Now().Add(
		time.Duration(time.Hour * 1),
	).Unix()
	claims[authMiddleware.ExpField] = originalExpirationTime
	claims["orig_iat"] = authMiddleware.TimeFunc().Unix()
	tokenString, err = authMiddleware.signedString(token, &Options{})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("it refreshes a token given a valid token that has not yet expired", func(t *testing.T) {

		generated, err := authMiddleware.RefreshIfRequired(tokenString, &Options{})

		assert.Nil(t, err)
		assert.IsType(t, &GeneratedToken{}, generated)
		assert.NotNil(t, generated.Token)
		assert.IsType(t, time.Time{}, generated.Expire)
		assert.Equal(t, generated.Expire.Unix(), originalExpirationTime)

	})
}

func generateJWKSJsons(t *testing.T) (string, string) {
	keyUsage := "sig"
	keyAlgorithm := jose.RS512
	publicKey, privateKey, err := generator.NewSigningKey(keyAlgorithm, 2048)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}

	privateKeyJwkBytes, err := privateKeyJwk.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}

	return string(publicKeyJwkBytes), string(privateKeyJwkBytes)
}

func TestJWKToken(t *testing.T) {
	publicKeyJwkBytes, privateKeyJwkBytes := generateJWKSJsons(t)

	// Create JWSProviderImpl instance
	authMiddleware, err := New(&GinJWTMiddleware[*Login]{
		DefaultOptions: &Options{
			SignerName: "test",
		},
		SigningAlgorithm: "RS512",
		Realm:            "test zone",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		SendCookie:       true,
		CookieName:       "jwt",
		Authenticator:    defaultAuthenticator,
		RefreshResponse: func(c *gin.Context, code int, token string, t time.Time) (*AuthResponse, error) {
			cookie, err := c.Cookie("jwt")
			if err != nil {
				return nil, err
			}

			return &AuthResponse{
				Code:    http.StatusOK,
				Token:   token,
				Expire:  t.Format(time.RFC3339),
				Message: "refresh successfully",
				Cookie:  cookie,
			}, nil
		},
	}, Signer{
		Name: "test",
		Keys: []Key{
			{
				Data:  publicKeyJwkBytes,
				IsJWK: true,
			},
			{
				Data:  privateKeyJwkBytes,
				IsJWK: true,
			},
		},
	})

	if err != nil {
		t.Fatal(err)
	}

	t.Run("Sign and Verify", func(t *testing.T) {
		payload := map[string]interface{}{
			"key1": "value1",
			"key2": float64(42), // needed because map[string]interface{} does is not roundtrip safe with ints
		}

		newToken := jwt.New(jwt.GetSigningMethod(authMiddleware.SigningAlgorithm))
		newClaims := newToken.Claims.(jwt.MapClaims)

		for key := range payload {
			newClaims[key] = payload[key]
		}

		// Sign the payload
		token, err := authMiddleware.signJWK(newToken, &Options{
			SignerName: "test",
		})
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify the token
		verifiedPayload, verified, err := authMiddleware.parseJWK(token, &Options{
			SignerName: "test",
		})

		assert.NoError(t, err)
		assert.NotEmpty(t, verified)
		assert.NotNil(t, verifiedPayload)

		// Compare the verified payload with the original
		assert.NoError(t, err)
		assert.Equal(t, newClaims, verifiedPayload.Claims.(jwt.MapClaims))
	})

	t.Run("Sign with invalid payload", func(t *testing.T) {
		_, err := authMiddleware.signJWK(nil, &Options{
			SignerName: "test",
		})
		assert.Error(t, err)
	})

	t.Run("Verify with invalid token", func(t *testing.T) {
		_, token, err := authMiddleware.parseJWK("invalid.token", &Options{
			SignerName: "test",
		})
		assert.Empty(t, token)
		assert.Error(t, err)
	})

	t.Run("Verify with non-existent verifier", func(t *testing.T) {
		payload := make(map[string]interface{})
		newToken := jwt.New(jwt.GetSigningMethod(authMiddleware.SigningAlgorithm))
		newClaims := newToken.Claims.(jwt.MapClaims)

		for key := range payload {
			newClaims[key] = payload[key]
		}

		token, err := authMiddleware.signJWK(newToken, &Options{
			SignerName: "test",
		})
		require.NoError(t, err)

		_, token, err = authMiddleware.parseJWK(token, &Options{
			SignerName: "non-existent",
		})
		assert.Empty(t, token)
		assert.Error(t, err)
	})

	mismatchedJwksPublicKey, mismatchedJwksPrivateKey := generateJWKSJsons(t)

	authMiddleware, err = New(&GinJWTMiddleware[*Login]{
		DefaultOptions: &Options{
			SignerName: "test",
		},
		SigningAlgorithm: "RS512",
		Realm:            "test zone",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		SendCookie:       true,
		CookieName:       "jwt",
		Authenticator:    defaultAuthenticator,
		RefreshResponse: func(c *gin.Context, code int, token string, t time.Time) (*AuthResponse, error) {
			cookie, err := c.Cookie("jwt")
			if err != nil {
				return nil, err
			}

			return &AuthResponse{
				Code:    http.StatusOK,
				Token:   token,
				Expire:  t.Format(time.RFC3339),
				Message: "refresh successfully",
				Cookie:  cookie,
			}, nil
		},
	}, Signer{
		Name: "test",
		Keys: []Key{
			{
				Data:  publicKeyJwkBytes,
				IsJWK: true,
			},
			{
				Data:  privateKeyJwkBytes,
				IsJWK: true,
			},
		},
	}, Signer{
		Name: "mismatched",
		Keys: []Key{
			{
				Data:  mismatchedJwksPublicKey,
				IsJWK: true,
			},
			{
				Data:  mismatchedJwksPrivateKey,
				IsJWK: true,
			},
		},
	})

	if err != nil {
		t.Fatal(err)
	}

	t.Run("Verify with mismatched key", func(t *testing.T) {
		// Generate a different key pair

		payload := map[string]interface{}{
			"key1": "value1",
			"key2": float64(42), // needed because map[string]interface{} does is not roundtrip safe with ints
		}

		newToken := jwt.New(jwt.GetSigningMethod(authMiddleware.SigningAlgorithm))
		newClaims := newToken.Claims.(jwt.MapClaims)

		for key := range payload {
			newClaims[key] = payload[key]
		}

		token, err := authMiddleware.signJWK(newToken, &Options{
			SignerName: "test",
		})
		require.NoError(t, err)

		_, parsed, err := authMiddleware.parseJWK(token, &Options{
			SignerName: "mismatched",
		})
		assert.Empty(t, parsed)
		assert.Error(t, err)
	})
}

func TestSignTokenString(t *testing.T) {

	publicKeyJwkBytes, privateKeyJwkBytes := generateJWKSJsons(t)

	// Create JWSProviderImpl instance
	authMiddleware, err := New(&GinJWTMiddleware[*Login]{
		DefaultOptions: &Options{
			SignerName: "test",
		},
		SigningAlgorithm: "RS512",
		Realm:            "test zone",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		SendCookie:       true,
		CookieName:       "jwt",
		Authenticator:    defaultAuthenticator,
		RefreshResponse: func(c *gin.Context, code int, token string, t time.Time) (*AuthResponse, error) {
			cookie, err := c.Cookie("jwt")
			if err != nil {
				return nil, err
			}

			return &AuthResponse{
				Code:    http.StatusOK,
				Token:   token,
				Expire:  t.Format(time.RFC3339),
				Message: "refresh successfully",
				Cookie:  cookie,
			}, nil
		},
	}, Signer{
		Name: "test",
		Keys: []Key{
			{
				Data:  publicKeyJwkBytes,
				IsJWK: true,
			},
			{
				Data:  privateKeyJwkBytes,
				IsJWK: true,
			},
		},
	})

	if err != nil {
		t.Fatal(err)
	}

	t.Run("it signs JWK tokens and returns a token string", func(t *testing.T) {

		payload := map[string]interface{}{
			"key1": "value1",
			"key2": float64(42), // needed because map[string]interface{} does is not roundtrip safe with ints
		}

		newToken := jwt.New(jwt.GetSigningMethod(authMiddleware.SigningAlgorithm))
		newClaims := newToken.Claims.(jwt.MapClaims)

		for key := range payload {
			newClaims[key] = payload[key]
		}

		token, err := authMiddleware.signedString(newToken, &Options{
			SignerName: "test",
		})

		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.NotEmpty(t, token)
	})
}

func ginTestHandler(auth *GinJWTMiddleware[*Login]) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	tonic.SetErrorHook(ErrHook)
	group := r.Group("/auth")
	group.Use(auth.MiddlewareFunc())
	{
		group.GET("/hello", helloHandler)
	}

	return r
}

func TestMiddlewareWithOpts(t *testing.T) {
	publicKeyJwkBytes, privateKeyJwkBytes := generateJWKSJsons(t)

	// Create JWSProviderImpl instance
	authMiddleware, err := New(&GinJWTMiddleware[*Login]{
		SigningAlgorithm: "RS512",
		Realm:            "test zone",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		SendCookie:       true,
		CookieName:       "jwt",
		Authenticator:    defaultAuthenticator,
		RefreshResponse: func(c *gin.Context, code int, token string, t time.Time) (*AuthResponse, error) {
			cookie, err := c.Cookie("jwt")
			if err != nil {
				return nil, err
			}

			return &AuthResponse{
				Code:    http.StatusOK,
				Token:   token,
				Expire:  t.Format(time.RFC3339),
				Message: "refresh successfully",
				Cookie:  cookie,
			}, nil
		},
	}, Signer{
		Name: "test",
		Keys: []Key{
			{
				Data:  publicKeyJwkBytes,
				IsJWK: true,
			},
			{
				Data:  privateKeyJwkBytes,
				IsJWK: true,
			},
		},
	})

	if err != nil {
		t.Fatal(err)
	}

	opt := &Options{
		"test",
	}

	t.Run("It sets DefaultOptions given a valid Option passed to the MiddlewareFunc", func(t *testing.T) {

		authMiddleware.MiddlewareFunc(opt)
		assert.Equal(t, authMiddleware.DefaultOptions, opt)

	})

	mappedClaims := jwt.MapClaims{
		"username": "admin",
		"password": "12345",
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
		"orig_iat": time.Now(),
		"nbf":      time.Now(),
	}

	authMiddleware.MiddlewareFunc(opt)
	handler := ginTestHandler(authMiddleware)
	testToken, err := authMiddleware.CreateToken(mappedClaims, opt)
	if err != nil {
		t.Fatal(err)
	}

	r := gofight.New()

	t.Run("it parses a JWK given opts passed to MiddlewareFunc", func(t *testing.T) {

		r.GET("/auth/hello").
			SetHeader(gofight.H{
				"Authorization": "Bearer " + testToken.Token,
			}).
			Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
				assert.Equal(t, http.StatusOK, r.Code)
			})

	})
}

func TestDefaultSigner(t *testing.T) {

	publicKeyJwkBytes, privateKeyJwkBytes := generateJWKSJsons(t)

	// Create JWSProviderImpl instance
	authMiddleware, err := New(&GinJWTMiddleware[*Login]{
		DefaultSigner: &Signer{
			Name: "test",
			Keys: []Key{
				{
					Data:  publicKeyJwkBytes,
					IsJWK: true,
				},
				{
					Data:  privateKeyJwkBytes,
					IsJWK: true,
				},
			},
		},
		SigningAlgorithm: "RS512",
		Realm:            "test zone",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		SendCookie:       true,
		CookieName:       "jwt",
		Authenticator:    defaultAuthenticator,
		RefreshResponse: func(c *gin.Context, code int, token string, t time.Time) (*AuthResponse, error) {
			cookie, err := c.Cookie("jwt")
			if err != nil {
				return nil, err
			}

			return &AuthResponse{
				Code:    http.StatusOK,
				Token:   token,
				Expire:  t.Format(time.RFC3339),
				Message: "refresh successfully",
				Cookie:  cookie,
			}, nil
		},
	})

	if err != nil {
		t.Fatal(err)
	}

	mappedClaims := jwt.MapClaims{
		"username": "admin",
		"password": "12345",
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
		"orig_iat": time.Now(),
		"nbf":      time.Now(),
	}

	handler := ginTestHandler(authMiddleware)
	testToken, err := authMiddleware.CreateToken(mappedClaims)
	if err != nil {
		t.Fatal(err)
	}

	r := gofight.New()

	t.Run("it signs using the default signer", func(t *testing.T) {

		r.GET("/auth/hello").
			SetHeader(gofight.H{
				"Authorization": "Bearer " + testToken.Token,
			}).
			Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
				assert.Equal(t, http.StatusOK, r.Code)
			})

	})

}
