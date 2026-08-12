package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

// Declare db globally so RegisterHandler can access it
var db *sql.DB

type Session struct {
	SessionID string
	UsersID   int
}

var Sessions = []Session{}

func generateSessionID() string {
	sessionID := make([]byte, 32)
	_, err := rand.Read(sessionID)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(sessionID)
}

// var sessions = map[string]int{
// 	"abc123":  2 ,
// }
// sessions[SessionID] = "abc123"
// sessions[UserID] = 2

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Parse and serve your HTML template file
		tmpl, err := template.ParseFiles("template/register.html")
		if err != nil {
			http.Error(w, "Could not load registration page", http.StatusInternalServerError)
			log.Printf("Template error: %v", err)
			return
		}
		tmpl.Execute(w, nil)
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		FirstName := r.FormValue("first_name")
		LastName := r.FormValue("last_name")
		Email := r.FormValue("email")
		Password := r.FormValue("password")

		if FirstName == "" || LastName == "" || Email == "" || Password == "" {
			http.Error(w, "All fields are required", http.StatusBadRequest)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error processing password", http.StatusInternalServerError)
			return
		}

		// 2. Insert into the database
		query := "INSERT INTO users (first_name, last_name, email, password_hash) VALUES (?, ?, ?, ?)"
		_, err = db.Exec(query, FirstName, LastName, Email, string(hashedPassword))

		if err != nil {
			log.Printf("Database insert error: %v", err)
			http.Error(w, "Failed to register user (Email might already exist)", http.StatusConflict)
			return
		}

		fmt.Fprintf(w, "Successfully received registration for: %s %s (%s)", FirstName, LastName, Email)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func LogHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templ, err := template.ParseFiles("template/login.html")
		if err != nil {
			http.Error(w, "Can not Login to the Page", http.StatusInternalServerError)
			return
		}
		templ.Execute(w, nil)
		return
	}

	Email := r.FormValue("email")
	Password := r.FormValue("password")

	if Email == "" || Password == "" {
		http.Error(w, "Please Fill in the space", http.StatusInternalServerError)
		return
	}

	var UserId int
	var UserPassword string

	query := "SELECT id , password_hash FROM users WHERE email = ?"
	err := db.QueryRow(query, Email).Scan(&UserId, &UserPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "No Such Account", http.StatusInternalServerError)
			return
		}
		http.Error(w, "Invalid User Input", http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(UserPassword), []byte(Password))
	if err != nil {
		http.Error(w, "Invalid email and password", http.StatusInternalServerError)
		return
	}
	// fmt.Fprint(w, "Successful")

	SessionID := generateSessionID()

	newSession := Session{
		SessionID: SessionID,
		UsersID:   UserId,
	}
	Sessions = append(Sessions, newSession)

	http.SetCookie(w, &http.Cookie{
		Name:  "session_id",
		Value: SessionID,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    SessionID,
		HttpOnly: true,
		Secure:   false,
		Path:     "/",
	})

}

func main() {

	http.HandleFunc("/login", LogHandler)
	http.HandleFunc("/register", RegisterHandler)

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env")
	}

	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s",
		dbUser,
		dbPassword,
		dbHost,
		dbPort,
		dbName,
	)

	// Assign to the global `db` variable (removed the `:=` short declaration)
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Could not connect to database:", err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal("Database ping failed:", err)
	}

	fmt.Println("Database connected successfully!")

	rows, err := db.Query("SHOW TABLES")
	if err != nil {
		log.Fatal("Query failed:", err)
	}
	defer rows.Close()

	fmt.Println("Tables in database:")

	for rows.Next() {
		var tableName string

		err := rows.Scan(&tableName)
		if err != nil {
			log.Fatal("Could not read table:", err)
		}

		fmt.Println("-", tableName)
	}

	fmt.Println("Server running on http://localhost:8080")

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println(err)
	}
}
