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

	"context"
	"encoding/json"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/genai"
	// "golang.org/x/vuln/scan"
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

type PracticeQuestion struct {
	ID            int
	MaterialID    int
	Question      string `json:"question"`
	OptionA       string `json:"option_a"`
	OptionB       string `json:"option_b"`
	OptionC       string `json:"option_c"`
	OptionD       string `json:"option_d"`
	CorrectAnswer string `json:"correct_answer"`
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

func EditingHandler(w http.ResponseWriter, r *http.Request) {

	// =========================
	// GET: Show the edit page
	// =========================
	if r.Method == http.MethodGet {

		id := r.URL.Query().Get("id")

		converToInt, err := strconv.Atoi(id)
		if err != nil {
			http.Error(w, "Invalid ID format", http.StatusBadRequest)
			return
		}

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

		query := "SELECT id, subject, topic, content, created_at FROM learning_materials WHERE id = ? AND user_id = ?"

		var material LearningMaterial

		err = db.QueryRow(query, converToInt, userID).Scan(
			&material.ID,
			&material.Subject,
			&material.Topic,
			&material.Content,
			&material.CreatedAt,
		)

		if err != nil {
			log.Printf("Editing error: %v", err)
			http.Error(w, "Failed to edit material", http.StatusInternalServerError)
			return
		}

		templ, err := template.ParseFiles("template/edit_material.html")
		if err != nil {
			http.Error(w, "Could not load edit page", http.StatusInternalServerError)
			return
		}

		templ.Execute(w, material)
		return
	}

	// =========================
	// POST: Update the material
	// =========================
	if r.Method == http.MethodPost {

		ID := r.FormValue("id")
		Subject := r.FormValue("subject")
		Topic := r.FormValue("topic")
		Content := r.FormValue("content")

		if Subject == "" {
			http.Error(w, "Error: Subject is required.", http.StatusBadRequest)
			return
		} else if Topic == "" {
			http.Error(w, "Error: Topic is required.", http.StatusBadRequest)
			return
		} else if Content == "" {
			http.Error(w, "Error: Content is required.", http.StatusBadRequest)
			return
		}

		converToInt, err := strconv.Atoi(ID)
		if err != nil {
			http.Error(w, "Invalid ID format", http.StatusBadRequest)
			return
		}

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

		query := "UPDATE learning_materials SET subject = ?, topic = ?, content = ? WHERE id = ? AND user_id = ?"

		_, err = db.Exec(query, Subject, Topic, Content, converToInt, userID)

		if err != nil {
			log.Printf("Editing error: %v", err)
			http.Error(w, "Failed to update material", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/learning", http.StatusSeeOther)
		return
	}

	// =========================
	// Any other method
	// =========================
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func StudyHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")

	convertoint, err := strconv.Atoi(id)

	if err != nil {
		http.Error(w, "Invalid ID format", http.StatusBadRequest)
		return
	}

	cookies, err := r.Cookie("session_id")

	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "Unauthorized: No Login Cookie Found", http.StatusUnauthorized)
			return
		}

		http.Error(w, "BadRequest", http.StatusBadRequest)
		return
	}

	SessionToken := cookies.Value

	var isAuthenticated bool
	var UseID int

	for i := 0; i < len(Sessions); i++ {

		if Sessions[i].SessionID == SessionToken {
			isAuthenticated = true
			UseID = Sessions[i].UsersID
		}
	}

	if !isAuthenticated {
		http.Error(w, "Unauthorized: Invalid session", http.StatusUnauthorized)
		return
	}

	var material LearningMaterial

	query := "SELECT id, subject, topic, content, created_at FROM learning_materials WHERE id=? AND user_id=?"

	err = db.QueryRow(query, convertoint, UseID).Scan(
		&material.ID,
		&material.Subject,
		&material.Topic,
		&material.Content,
		&material.CreatedAt,
	)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get practice questions
	var questions []PracticeQuestion

	questionQuery := `
		SELECT id, material_id, question, option_a, option_b, option_c, option_d, correct_answer
		FROM practice_questions
		WHERE material_id = ?
	`

	rows, err := db.Query(questionQuery, convertoint)

	if err != nil {
		http.Error(w, "Could not load practice questions", http.StatusInternalServerError)
		return
	}

	defer rows.Close()

	for rows.Next() {

		var question PracticeQuestion

		err := rows.Scan(
			&question.ID,
			&question.MaterialID,
			&question.Question,
			&question.OptionA,
			&question.OptionB,
			&question.OptionC,
			&question.OptionD,
			&question.CorrectAnswer,
		)

		if err != nil {
			http.Error(w, "Could not read practice question", http.StatusInternalServerError)
			return
		}

		questions = append(questions, question)
	}

	if err = rows.Err(); err != nil {
		http.Error(w, "Error reading questions", http.StatusInternalServerError)
		return
	}

	templ, err := template.ParseFiles("template/study.html")

	if err != nil {
		http.Error(w, "Could Not Load The Study Page", http.StatusInternalServerError)
		return
	}

	data := struct {
		Material  LearningMaterial
		Questions []PracticeQuestion
	}{
		Material:  material,
		Questions: questions,
	}

	templ.Execute(w, data)
}

func add(a int, b int) int {
	return a + b
}

func PracticeHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	converToint, err := strconv.Atoi(id)
	if err != nil {
		http.Error(w, "Invalid ID format", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie("session_id")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "Unauthorized: No login cookie found", http.StatusUnauthorized)
			return
		}
		http.Error(w, "BadRequest", http.StatusBadRequest)
		return
	}
	SessionToken := cookie.Value

	var isAuthenticated bool
	// var UseID int

	for i := 0; i < len(Sessions); i++ {
		if Sessions[i].SessionID == SessionToken {
			isAuthenticated = true
			// UseID = Sessions[i].UsersID
			break
		}
	}

	if !isAuthenticated {
		http.Error(w, "Unauthorized: Invalid session", http.StatusUnauthorized)
		return
	}

	var questions []PracticeQuestion

	query := "SELECT id , material_id, question,option_a ,option_b , option_c ,  option_d , correct_answer FROM practice_questions WHERE material_id = ?"

	// err = db.QueryRow(query , converToint,UseID)
	rows, err := db.Query(query, converToint)

	if err != nil {
		http.Error(w, "Error retrieving learning materials", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var question PracticeQuestion
		err := rows.Scan(&question.ID, &question.MaterialID, &question.Question, &question.OptionA, &question.OptionB, &question.OptionC, &question.OptionD, &question.CorrectAnswer)
		if err != nil {
			continue
		}
		questions = append(questions, question)

	}
	if err := rows.Err(); err != nil {
		http.Error(w, "Error reading practice questions", http.StatusInternalServerError)
		return
	}

	// templ, err := template.ParseFiles("template/practice.html")
	templ, err := template.New("practice.html").
		Funcs(template.FuncMap{
			"add": add,
		}).
		ParseFiles("template/practice.html")

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = templ.Execute(w, questions)
	if err != nil {
		http.Error(w, "Could not load practice page", http.StatusInternalServerError)
		return
	}

}

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env")
	}

	Api_Key := os.Getenv("GEMINI_API_KEY")
	ctx := context.Background()
	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey: Api_Key,
	})

	schema := &genai.Schema{
		Type: genai.TypeObject,
		Properties: map[string]*genai.Schema{
			"question": {
				Type: genai.TypeString,
			},
			"option_a": {
				Type: genai.TypeString,
			},
			"option_b": {
				Type: genai.TypeString,
			},
			"option_c": {
				Type: genai.TypeString,
			},
			"option_d": {
				Type: genai.TypeString,
			},
			"correct_answer": {
				Type: genai.TypeString,
				Enum: []string{"A", "B", "C", "D"},
			},
		},

		Required: []string{
			"question",
			"option_a",
			"option_b",
			"option_c",
			"option_d",
			"correct_answer",
		},
	}

	response, err := client.Models.GenerateContent(
		ctx,
		"gemini-3.6-flash",
		[]*genai.Content{
			genai.NewContentFromText("Generate one multiple-choice question about Go structs. Provide four options and identify the correct answer.", genai.RoleUser),
		}, &genai.GenerateContentConfig{ResponseMIMEType: "application/json", ResponseSchema: schema},
	)

	if err != nil {
		log.Fatal("Gemini error:", err)
	}

	jsonData := response.Text()
	var generatedQuestion PracticeQuestion

	err = json.Unmarshal([]byte(jsonData), &generatedQuestion)
	if err != nil {
		log.Fatalf("Failed to unmarshal Gemini response: %v", err)
	}

	fmt.Println("Generated question:", generatedQuestion.Question)
	fmt.Println("Option A:", generatedQuestion.OptionA)
	fmt.Println("Option B:", generatedQuestion.OptionB)
	fmt.Println("Option C:", generatedQuestion.OptionC)
	fmt.Println("Option D:", generatedQuestion.OptionD)
	fmt.Println("Correct answer:", generatedQuestion.CorrectAnswer)
	// println(response.Text())

	http.HandleFunc("/practice", PracticeHandler)
	http.HandleFunc("/study", StudyHandler)
	http.HandleFunc("/edit", EditingHandler)
	http.HandleFunc("/delete", DeleteHandler)
	http.HandleFunc("/learning", learning_materials)

	http.HandleFunc("/logout", LogoutHandler)
	http.HandleFunc("/dashboard", DashboardHandler)
	http.HandleFunc("/login", LogHandler)
	http.HandleFunc("/register", RegisterHandler)

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
