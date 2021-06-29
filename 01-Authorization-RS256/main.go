package main

// sorted following imports for best readability.
import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/auth0/go-jwt-middleware"
	"github.com/codegangsta/negroni"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
)

type Response struct {
	Message string `json:"message"`
}

// TODO: a brief desciption here would be nice.
type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

// TODO: Add some description to this struct. After going through the program I understood what it's
//			 being used for. As an end developer, if I am trying to use this sample as a reference to
//			 use Auth0 in my own program, I'd definitely be curious to understand if following struct
//			 is required to be modifed for my purpose or not. These details are best abstracted within
//			 a go module of its own so that end developer don't have to worry about these at all.
type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

func main() {

	// TODO: If simplicity is desired, it's best to keep the environment variable definition
	//			outside of current app. Although using 'godotenv' gets the job done but it also
	//			forces the user to understand what's being done (especially if the end user is
	//			not already familiar with loading of '.env' files) by this lib and statement.
	//			These are already set correctly for `docker run ...` within launch scripts.
	//      Recommended alternate approaches are -
	//			=== Out of process environment declaration ===
	//			1. Let the user expose these environment variables on CLI before invoking this
	// 				 program (say using `export key=val`. README shall be updated accordingly.
	//			2. The program shall validate availability of these environment variable right
	//				 at start and abort with appropriate error if required variables are not
	//				 found in current set of environment variables.
	//			=== Use go native flag package ===
	//			Since the program is intended to be self sufficient and there are no complex
	//			requirements around required parameters, it's best to use https://golang.org/pkg/flag/
	//			to pass value of required parameters to this program. This way, the reader gets the
	//			full gist of parameters required to run and they can adapt it accordingly while
	//			using the sample as a reference for integration in their own go project.
	// TODO: To summarize, keep the example as simple as it can be for it be most usable for
	//			 widest possible audience.
	err := godotenv.Load()
	if err != nil {
		log.Print("Error loading .env file")
	}

	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		// FIXME: Not functional any more. Update as per latest interface contract
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			// Verify 'aud' claim
			aud := os.Getenv("AUTH0_AUDIENCE")
			checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
			if !checkAud {
				// FIXME: Update error text to comply with go idioms. Further details at -
				//				https://github.com/golang/go/wiki/CodeReviewComments#error-strings
				return token, errors.New("Invalid audience.")
			}
			// Verify 'iss' claim
			iss := "https://" + os.Getenv("AUTH0_DOMAIN") + "/"
			checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
			if !checkIss {
				// FIXME: Update error text to comply with go idioms.
				return token, errors.New("Invalid issuer.")
			}

			cert, err := getPemCert(token)
			if err != nil {
				// FIXME: panic shall be avoided in middleware. This function allows returning
				//				the error and that shall be used instead of panic here.
				panic(err.Error())
			}

			result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
			return result, nil
		},
		// TODO: does Auth0 support any other signing algo? If so, a comment here shall be added
		//			 updating about possible options with auth0 doc link as may be appropriate.
		SigningMethod: jwt.SigningMethodRS256,
	})

	// TODO: Add description when and why following CORS policy handler is required. Presumably this
	//			 is required for a frontend development environment. The intent is not clear from the
	//			 code and adding a description will definitely help.
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowCredentials: true,
		AllowedHeaders:   []string{"Authorization"},
	})

	r := mux.NewRouter()

	// This route is always accessible
	r.Handle("/api/public", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		message := "Hello from a public endpoint! You don't need to be authenticated to see this."
		responseJSON(message, w, http.StatusOK)
	}))

	// This route is only accessible if the user has a valid access_token
	// We are chaining the jwtmiddleware middleware into the negroni handler function which will check
	// for a valid token.
	r.Handle("/api/private", negroni.New(
		negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			message := "Hello from a private endpoint! You need to be authenticated to see this."
			responseJSON(message, w, http.StatusOK)
		}))))

	// This route is only accessible if the user has a valid access_token with the read:messages scope
	// We are chaining the jwtmiddleware middleware into the negroni handler function which will check
	// for a valid token and scope.
	r.Handle("/api/private-scoped", negroni.New(
		negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeaderParts := strings.Split(r.Header.Get("Authorization"), " ")
			token := authHeaderParts[1]

			hasScope := checkScope("read:messages", token)

			if !hasScope {
				message := "Insufficient scope."
				responseJSON(message, w, http.StatusForbidden)
				return
			}
			message := "Hello from a private endpoint! You need to be authenticated to see this."
			responseJSON(message, w, http.StatusOK)
		}))))

	handler := c.Handler(r)
	http.Handle("/", r)
	fmt.Println("Listening on http://localhost:3010")
	http.ListenAndServe("0.0.0.0:3010", handler)
}

type CustomClaims struct {
	Scope string `json:"scope"`
	jwt.StandardClaims
}

func checkScope(scope string, tokenString string) bool {
	token, _ := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		cert, err := getPemCert(token)
		if err != nil {
			return nil, err
		}
		result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
		return result, nil
	})

	claims, ok := token.Claims.(*CustomClaims)

	hasScope := false
	if ok && token.Valid {
		result := strings.Split(claims.Scope, " ")
		for i := range result {
			if result[i] == scope {
				hasScope = true
				// TODO: we have found our scope, there's no need to iterate any longer.
				// 				either return, OR break is recommended here
			}
		}
	}

	return hasScope
}

func getPemCert(token *jwt.Token) (string, error) {
	cert := ""
	resp, err := http.Get("https://" + os.Getenv("AUTH0_DOMAIN") + "/.well-known/jwks.json")

	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	// TODO: make following block self explanatory somehow. Not able to easily understand a flow
	// 			 is usually a sign of something is not being done right.
	//			 We may want to abstract all these complexities in a shared go module instead.
	for k, _ := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		// FIXME: Update error text to comply with go idioms.
		err := errors.New("Unable to find appropriate key.")
		return cert, err
	}

	return cert, nil
}

func responseJSON(message string, w http.ResponseWriter, statusCode int) {
	response := Response{message}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(jsonResponse)
}
