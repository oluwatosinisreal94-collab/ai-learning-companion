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
	"strconv"
	"time"

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

type LearningMaterial struct {
	ID        int
	Subject   string
	Topic     string
	Content   string
	CreatedAt string
}

var materials []LearningMaterial

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

	// http.SetCookie(w, &http.Cookie{
	// 	Name:  "session_id",
	// 	Value: SessionID,
	// })

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    SessionID,
		HttpOnly: true,
		Secure:   false,
		Path:     "/",
	})

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	return
}

func DashboardHandler(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("session_id")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "Unauthorized: No login cookie found", http.StatusUnauthorized)
			return
		}

		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	sessionToken := cookie.Value

	var isAuthenticated bool
	var userID int

	for i := 0; i < len(Sessions); i++ {
		if Sessions[i].SessionID == sessionToken {
			isAuthenticated = true
			userID = Sessions[i].UsersID
			break
		}
	}

	if !isAuthenticated {
		http.Error(w, "Unauthorized: Invalid session", http.StatusUnauthorized)
		return
	}

	var materialCount int

	query := "SELECT COUNT(*) FROM learning_materials WHERE user_id = ?"

	err = db.QueryRow(query, userID).Scan(&materialCount)
	if err != nil {
		http.Error(w, "Error counting learning materials", http.StatusInternalServerError)
		return
	}

	var FirstName, LastName string

	query = "SELECT first_name, last_name FROM users WHERE id = ?"
	err = db.QueryRow(query, userID).Scan(&FirstName, &LastName)
	if err != nil {
		http.Error(w, "Error retrieving profile", http.StatusInternalServerError)
		return
	}

	data := struct {
		FirstName     string
		LastName      string
		MaterialCount int
	}{
		FirstName:     FirstName,
		LastName:      LastName,
		MaterialCount: materialCount,
	}

	templ, err := template.ParseFiles("template/dashboard.html")
	if err != nil {
		http.Error(w, "Could not load dashboard", http.StatusInternalServerError)
		return
	}
	templ.Execute(w, data)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "Could Not Be Fund", http.StatusInternalServerError)
		return
	}

	sessionToken := cookie.Value

	for i := 0; i < len(Sessions); i++ {
		if Sessions[i].SessionID == sessionToken {
			Sessions = append(Sessions[:i], Sessions[i+1:]...)
			break
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
		Secure:   false,
		Path:     "/",
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)

}

func learning_materials(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "Unauthorized: No login cookie found", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	sessionToken := cookie.Value

	var isAuthenticated bool
	var userID int

	for i := 0; i < len(Sessions); i++ {
		if Sessions[i].SessionID == sessionToken {
			isAuthenticated = true
			userID = Sessions[i].UsersID
			break
		}
	}
	if !isAuthenticated {
		http.Error(w, "Unauthorized: Invalid session", http.StatusUnauthorized)
		return
	}

	// Handle POST: Insert new material when form is submitted
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		subject := r.FormValue("subject")
		topic := r.FormValue("topic")
		content := r.FormValue("content")

		if subject == "" || topic == "" || content == "" {
			http.Error(w, "All fields are required", http.StatusBadRequest)
			return
		}

		insertQuery := "INSERT INTO learning_materials (user_id, subject, topic, content) VALUES (?, ?, ?, ?)"
		_, err = db.Exec(insertQuery, userID, subject, topic, content)
		if err != nil {
			log.Printf("Insert error: %v", err)
			http.Error(w, "Failed to save material", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/learning", http.StatusSeeOther)
		return
	}

	// Handle GET: Fetch and display materials
	query := "SELECT id, subject, topic, content, created_at FROM learning_materials WHERE user_id = ?"
	rows, err := db.Query(query, userID)
	if err != nil {
		http.Error(w, "Error retrieving learning materials", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var userMaterials []LearningMaterial
	for rows.Next() {
		var material LearningMaterial
		err := rows.Scan(&material.ID, &material.Subject, &material.Topic, &material.Content, &material.CreatedAt)
		if err != nil {
			continue
		}
		userMaterials = append(userMaterials, material)
	}

	data := struct {
		Materials []LearningMaterial
	}{
		Materials: userMaterials,
	}

	templ, err := template.ParseFiles("template/learning_materials.html")
	if err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Could not load materials page", http.StatusInternalServerError)
		return
	}
	templ.Execute(w, data)
}

func DeleteHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	id := r.FormValue("delete")
	ConvertIdToInt, err := strconv.Atoi(id)
	if err != nil {
		http.Error(w, "Invalid ID format", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie("session_id")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "Unauthorized: No login cookie found", http.StatusInternalServerError)
			return
		}
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	sessionToken := cookie.Value

	var isAuthenticated bool
	var userID int

	for i := 0; i < len(Sessions); i++ {
		if Sessions[i].SessionID == sessionToken {
			isAuthenticated = true
			userID = Sessions[i].UsersID
			break
		}
	}
	if !isAuthenticated {
		http.Error(w, "Unauthorized: Invalid session", http.StatusUnauthorized)
		return
	}

	query := "DELETE FROM learning_materials WHERE id = ? AND user_id = ?"
	_, err = db.Exec(query, ConvertIdToInt, userID)
	if err != nil {
		log.Printf("Delete error: %v", err)
		http.Error(w, "Failed to delete material", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/learning", http.StatusSeeOther)

}


func main() {

	http.HandleFunc("/delete", DeleteHandler)
	http.HandleFunc("/learning", learning_materials)

	http.HandleFunc("/logout", LogoutHandler)
	http.HandleFunc("/dashboard", DashboardHandler)
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
