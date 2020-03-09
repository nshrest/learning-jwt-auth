// Package main creates a server which handles few api endpoints and restricted api endpoint
// which can be be eccessed via jwt token based authentication.
// Learning JWT authentication and its implementation to go webpages.
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

//
// GLOBAL SCOPED VARS
//

var db *sql.DB

//
// STRUCTS / MODELS DEFINITION
//

// A User struct holds the information about users used for signup/login
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// A JWT struct holds the jwt token for protected endpoint verification
type JWT struct {
	Token string `json:"token"`
}

// A Error struct holds the custom error message which will be sent to clients back if needed.
type Error struct {
	Message string `json:"message"`
}

//
// UTIL FUNCTION
//

// func respondWithError creates response with error message as a body
func respondWithError(w http.ResponseWriter, status int, error Error) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
}

// func responseJSON creates response with user (without password) as a body
// also writes header as "Content-Type": "application/json"
func responseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}

func generateToken(user User) (string, error) {
	var err error

	// jwt = header.payload.secret
	// set secret for jwt token
	secret := "topsecret"

	// generate a new token which takes a signingmethod(algorithm like HS256)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user":   user.Username,
		"issuer": "pe-info",
	})

	// Test how does the token looks like
	// spew.Dump(token)
	// return "", nil

	// sign the token with secret key which would be a final token
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		log.Fatal(err)
	}

	return tokenString, nil
}

//
// HANDLER FUNCTIONS DEFINITION
//

// signup handler func accepts responsewriter interface and request struct.
// ResponseWriter { Header() Header, Write([]byte) (int, error), WriteHeader(statusCode int) }
// Request { Method string, URL *url.URL, Header Header, Body io.ReadCloser, Form url.Values, ctx context.Context}   ... many more in structs
// but those are the important ones.
func signup(w http.ResponseWriter, r *http.Request) {

	// w.Write([]byte("Successfully called signup"))
	// extracts user input as username and password from request body, encrypt password and stores it back to database
	// after successfull (unsuccessfull) operation, return back response to client.
	var user User
	var error Error

	// NewDecoder returns a decoder struct from a request and Decode method converts the json to provided struct
	json.NewDecoder(r.Body).Decode(&user)

	// check if any empty values provided in request from clinet.
	if user.Username == "" {
		log.Println("Error: signup endpoint invoked")
		error.Message = "Username is missing."
		// send Bad Request http.StatusBadRequest 400
		// w.WriteHeader(http.StatusBadRequest)
		// json.NewEncoder(w).Encode(error)
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		log.Println("Error: signup endpoint invoked")
		error.Message = "Password is missing."
		// send Bad Request http.StatusBadRequest 400
		// w.WriteHeader(http.StatusBadRequest)
		// json.NewEncoder(w).Encode(error)
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	if error.Message == "" {
		log.Println("signup endpoint invoked")
	}

	// encrypt password to store in db
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		log.Fatal(err)
	}

	user.Password = string(hash)
	// Add user to db
	stmt := "insert into users (username, password) values($1, $2) RETURNING id;"
	err = db.QueryRow(stmt, user.Username, user.Password).Scan(&user.ID)
	if err != nil {
		error.Message = "database error"
		respondWithError(w, http.StatusInternalServerError, error)
		return
	}

	// set pasword to nil for client response
	user.Password = ""

	// write header and response
	w.Header().Set("Content-Type", "application/json")
	responseJSON(w, user)

}

// func login is  handler function which accepts a responsewriter interface and pointer to a response.
func login(w http.ResponseWriter, r *http.Request) {
	// w.Write([]byte("successfully called login"))
	var user User
	var jwt JWT
	var error Error

	log.Println("login endpoint invoked")

	// extract user info from request and update user variable
	json.NewDecoder(r.Body).Decode(&user)

	// Check if username and password is not empty
	if user.Username == "" {
		error.Message = "Username is missing"
		respondWithError(w, http.StatusBadRequest, error)
		log.Println("login unsuccessful")
		return
	}
	if user.Password == "" {
		error.Message = "Password is missing"
		respondWithError(w, http.StatusBadRequest, error)
		log.Println("login unsuccessful")
		return
	}

	// user password from the login request (plain text)
	// to comapare later with hashed password from db
	userpassword := user.Password

	// check if user exists in database
	row := db.QueryRow("select * from users where username=$1", user.Username)
	err := row.Scan(&user.ID, &user.Username, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			error.Message = "Username not found"
			respondWithError(w, http.StatusBadRequest, error)
			log.Println("login unsuccessful")
			return
		}
		log.Println("login unsuccessful.. sth wrong terminating...")
		log.Fatal(err)

	}

	// compare hash password to user provided password
	hashedpassword := user.Password
	isValidPassword := ComparePasswords(hashedpassword, []byte(userpassword))
	if isValidPassword {
		// generate token by passing user
		token, err := generateToken(user)
		if err != nil {
			log.Fatal(err)
		}

		jwt.Token = token
		// fmt.Println(token)
		// setting client response with JWT token
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		responseJSON(w, jwt)
		log.Println("login success")
	} else {
		error.Message = "Invalid Password"
		respondWithError(w, http.StatusUnauthorized, error)
		return
	}

}

// ComparePasswords compare hashed password from db with user provided password
// from login post methods
func ComparePasswords(hashedPassword string, password []byte) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), password)
	if err != nil {
		log.Println("login unsuccessful", err)
		return false
	}
	return true
}

// TokenVerifyMiddleware is a middleware function sits between protected endpoint and protected endpoint handle function.
// This outputs the protected endpoint handle function which calls the protected endpoint after verifiying auth.
// This does by validating token from the header with secret key
// for every protected endpoint just call this tokenverifymiddleware onwards....
func TokenVerifyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorObject Error

		// find the token part from header Authorization (bearer token)
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")

		if len(bearerToken) == 2 {
			authToken := bearerToken[1]

			// Parse, validate, and return a token. (When Parse is successful - token's valid field is true, signature field is written)
			// keyFunc will receive the parsed token and should return the key for validating.
			// If everything is kosher, err will be nil
			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}

				return []byte("topsecret"), nil
			})

			if error != nil {
				errorObject.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}

			if token.Valid {
				// ServeHTTP calls next(w, r)  - in our case next is protectedEndpoint(w, r)
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}
		} else {
			errorObject.Message = "Invalid token."
			respondWithError(w, http.StatusUnauthorized, errorObject)
			return
		}
	})
}

// func protectedEndpoint is a handler function which accepts responsewriter interface and a pointer to a response type
func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	responseJSON(w, "protected endpoint invoked")
	log.Println("protected endpoint invoked")
}

//
// MAIN FUNCTION
//

func main() {
	//  DB connect (using builtin sql package instead documents says jet package.)
	pgURL, err := pq.ParseURL("postgres://loiocvro:NX6fuGUBk12YapRmI0un2Sf_TDheGsld@raja.db.elephantsql.com:5432/loiocvro")
	if err != nil {
		log.Fatal(err)
	}

	// Test what is inside pgURL
	// fmt.Println(pgURL)
	// dbname=loiocvro host=raja.db.elephantsql.com password=NX6fuGUBk12YapRmI0un2Sf_TDheGsld port=5432 user=loiocvro
	db, err = sql.Open("postgres", pgURL)
	if err != nil {
		log.Fatal(err)
	}

	// Test what is inside db
	// fmt.Println(db)
	// &{0 {dbname=loiocvro host=raja.db.elephantsql.com password=NX6fuGUBk12YapRmI0un2Sf_TDheGsld port=5432 user=loiocvro 0x9f3b70} 0 {0 0} [] map[] 0 0 0xc0000560c0 0xc00001a240 false map[] map[] 0 0 0 <nil> 0 0 0 0x491ce0}
	err = db.Ping()

	// NewRouter returns a new router instance. (pointer)
	router := mux.NewRouter()

	// A router.HandleFunc registers routes to be matched and dispatches a handler. (pointer to a route struct)
	// route now has various methods and one we use to respond if the req method is get/post called Methods
	// signup route is registered which calls signup handle function when http.Methods is POST
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleware(protectedEndpoint)).Methods("GET")

	// start server on localhost port 8080
	log.Println("Listen on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", router))
}
