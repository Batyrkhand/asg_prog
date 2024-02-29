package main

import (
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
	"html/template"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB
var log *logrus.Logger
var requestMutex sync.Mutex
var lastRequestTime time.Time

type Product struct {
	gorm.Model
	Name  string
	Price float64
}
type User struct {
	gorm.Model
	Name              string
	Email             string
	PasswordHash      string
	EmailVerified     bool
	ConfirmationToken string
	ResetToken        string
	ResetTokenExpiry  time.Time // New field for reset token expiry
	IsAdmin           bool      // New field for admin status

}

func main() {
	initLogger()
	initDB()
	rand.Seed(time.Now().UnixNano())
	r := mux.NewRouter()
	r.HandleFunc("/register", handleRegister).Methods("POST", "GET")
	r.HandleFunc("/register1", serveRegistrationPage).Methods("GET")
	r.HandleFunc("/confirm", handleConfirmEmail).Methods("GET")
	r.HandleFunc("/login", handleLogin).Methods("POST", "GET")
	r.HandleFunc("/admin", handleAdmin).Methods("GET")
	r.HandleFunc("/update", handleUpdate).Methods("POST")
	r.HandleFunc("/delete", handleDelete).Methods("POST")
	r.HandleFunc("/", handleIndex).Methods("GET")
	r.HandleFunc("/main", handleMain).Methods("GET")
	r.HandleFunc("/reset", handleResetRequest).Methods("POST", "GET") // Changed to direct to handleResetRequest
	r.HandleFunc("/reset/{token}", handlePasswordReset).Methods("GET", "POST")
	r.HandleFunc("/reset1", serveResetPage).Methods("GET")
	r.HandleFunc("/create", handleUserCreation).Methods("POST")     // For creating a new user
	r.HandleFunc("/update", handleUserUpdate).Methods("POST")       // For updating a user
	r.HandleFunc("/delete", handleUserDeletion).Methods("POST")     // For deleting a user
	r.HandleFunc("/create1", handleProductCreation).Methods("POST") // For creating a new product
	r.HandleFunc("/update", handleProductUpdate).Methods("POST")    // For updating a product
	r.HandleFunc("/delete1", handleProductDeletion).Methods("POST") // For deleting a product

	// Other routes...
	r.Use(rateLimitingMiddleware)

	log.Fatal(http.ListenAndServe(":8080", r))
}

func initLogger() {
	log = logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	file, err := os.OpenFile("logfile.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.SetOutput(file)
	} else {
		log.Error("Failed to open log file:", err)
	}
	log.SetOutput(io.MultiWriter(os.Stdout, file))
}

func initDB() {
	dsn := "user=postgres password=jansatov04 dbname=postgres sslmode=disable host=localhost port=3000"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	_ = db.AutoMigrate(&User{}, &Product{})
}

const maxRequestsPerSecond = 100

func rateLimitingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMutex.Lock()
		defer requestMutex.Unlock()

		timeElapsed := time.Since(lastRequestTime)
		timeRequiredPerRequest := time.Second / time.Duration(maxRequestsPerSecond)

		if timeElapsed < timeRequiredPerRequest {
			log.Warn("Rate limit exceeded")
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		lastRequestTime = time.Now()
		next.ServeHTTP(w, r)
	})
}
func handleIndex(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func handleUserCreation(w http.ResponseWriter, r *http.Request) {
	// Extract user data from the form
	name := r.FormValue("name")
	email := r.FormValue("email")
	password := r.FormValue("password")

	// Hash the password before storing it
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("Failed to hash password:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Create a new user record in the database
	newUser := User{
		Name:          name,
		Email:         email,
		PasswordHash:  string(hashedPassword),
		EmailVerified: true,  // Assuming email verification is required
		IsAdmin:       false, // Set as needed
	}
	if err := db.Create(&newUser).Error; err != nil {
		log.Error("Failed to create user:", err)
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Optionally, send a confirmation email to the user

	// Redirect the user to an appropriate page
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func handleUserDeletion(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from the form
	userIDStr := r.FormValue("userIdDelete")

	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid User ID", http.StatusBadRequest)
		return
	}

	var user User
	if err := db.First(&user, userID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if err := db.Delete(&user).Error; err != nil {
		log.Error("Failed to delete user:", err)
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	// Redirect the user to an appropriate page
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func handleProductCreation(w http.ResponseWriter, r *http.Request) {
	// Extract product data from the form
	name := r.FormValue("name")
	priceStr := r.FormValue("price")
	price, err := strconv.ParseFloat(priceStr, 64)
	log.Printf("Received product data - Name: %s, Price: %s\n", name, priceStr)

	if err != nil {
		http.Error(w, "Invalid price", http.StatusBadRequest)
		return
	}
	newProduct := Product{
		Name:  name,
		Price: price,
	}
	if err := db.Create(&newProduct).Error; err != nil {
		log.Error("Failed to create product:", err)
		http.Error(w, "Failed to create product", http.StatusInternalServerError)
		return
	}
	log.Println("Product created successfully:", newProduct)

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func handleProductDeletion(w http.ResponseWriter, r *http.Request) {
	// Extract product ID from the form
	productIDStr := r.FormValue("productIdDelete")

	productID, err := strconv.ParseUint(productIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid Product ID", http.StatusBadRequest)
		return
	}

	var product Product
	if err := db.First(&product, productID).Error; err != nil {
		http.Error(w, "Product not found", http.StatusNotFound)
		return
	}

	if err := db.Delete(&product).Error; err != nil {
		log.Error("Failed to delete product:", err)
		http.Error(w, "Failed to delete product", http.StatusInternalServerError)
		return
	}

	// Redirect the user to an appropriate page
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	email := r.FormValue("email")
	password := r.FormValue("password")

	// Hash the password before storing it
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("Failed to hash password:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Generate a confirmation token
	confirmationToken := generateConfirmationToken()

	newUser := User{
		Name:              name,
		Email:             email,
		PasswordHash:      string(hashedPassword),
		ConfirmationToken: confirmationToken,
	}
	if err := db.Create(&newUser).Error; err != nil {
		log.Error("Failed to create user:", err)
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	sendConfirmationEmail(newUser.Email, confirmationToken)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleResetRequest(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")

	var user User
	result := db.Where("email = ?", email).First(&user)
	if result.Error != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	token := generatePasswordResetToken()
	user.ResetTokenExpiry = time.Now().Add(time.Hour * 1)
	user.ResetToken = token

	if err := db.Save(&user).Error; err != nil {
		log.Error("Failed to save reset token:", err)
		http.Error(w, "Failed to initiate password reset", http.StatusInternalServerError)
		return
	}

	// Send an email to the user with the password reset link
	sendPasswordResetEmail(user.Email, token)

	// Redirect the user to the login page
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]

	// Handle GET request to render reset form
	if r.Method == http.MethodGet {
		// Render reset form with token
		renderResetForm(w, token)
		return
	}

	// Handle POST request to update password
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	// Validate password and confirm password match
	if password != confirmPassword {
		http.Error(w, "Passwords do not match", http.StatusBadRequest)
		return
	}

	// Update password in the database
	err := updateUserPassword(token, password)
	if err != nil {
		// Handle error
		http.Error(w, "Failed to reset password", http.StatusInternalServerError)
		return
	}

	// Redirect to login page after successful password reset
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// Function to render reset form with token
func renderResetForm(w http.ResponseWriter, token string) {
	tmpl, err := template.ParseFiles("reset.html")
	if err != nil {
		// Handle error
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Render reset form with token
	err = tmpl.Execute(w, struct{ Token string }{Token: token})
	if err != nil {
		// Handle error
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// Function to update user's password in the database
func updateUserPassword(token, password string) error {
	// Find user by reset token
	var user User
	result := db.Where("reset_token = ?", token).First(&user)
	if result.Error != nil {
		// Handle error (invalid or expired token)
		return result.Error
	}

	// Update user's password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		// Handle error
		return err
	}
	user.PasswordHash = string(hashedPassword)
	user.ResetToken = ""

	// Save updated user in the database
	if err := db.Save(&user).Error; err != nil {
		// Handle error
		return err
	}

	return nil
}

func sendPasswordResetEmail(email, token string) {
	// Configure the email sender
	sender := gomail.NewMessage()
	sender.SetHeader("From", "mereke61a@gmail.com") // Replace with your email address
	sender.SetHeader("To", email)
	sender.SetHeader("Subject", "Password Reset")
	body := fmt.Sprintf("Click the following link to reset your password: http://localhost:8080/reset/%s", token)
	sender.SetBody("text/html", body)

	// Replace these credentials with your actual email credentials
	dialer := gomail.NewDialer("smtp.gmail.com", 587, "mereke61a@gmail.com", "rire boaf odvl rsmn	")

	// Send the email
	if err := dialer.DialAndSend(sender); err != nil {
		log.Error("Failed to send password reset email:", err)
		// Handle the error appropriately
	}
}

func generatePasswordResetToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
func handleConfirmEmail(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")

	var user User
	result := db.Where("confirmation_token = ?", token).First(&user)
	if result.Error != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Update user's EmailVerified field
	user.EmailVerified = true
	user.ConfirmationToken = ""
	db.Save(&user)

	// Redirect to the login page
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// If it's a GET request, render the login page
		renderLoginPage(w, "", "")
		return
	}

	// If it's a POST request, handle the login form submission
	email := r.FormValue("email")
	password := r.FormValue("password")
	log.Info("Attempting login for email:", email)

	var user User
	result := db.Where("email = ?", email).First(&user)
	if result.Error != nil || !user.EmailVerified {
		renderLoginPage(w, "Invalid credentials or email not verified", "")
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		renderLoginPage(w, "Invalid credentials", "")
		return
	}

	// Check if user is admin
	if user.IsAdmin {
		// Redirect to admin page
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	// Redirect to main page for non-admin users
	http.Redirect(w, r, "/main", http.StatusSeeOther)
}
func handleAdmin(w http.ResponseWriter, r *http.Request) {
	// Check if user is admin
	isAdmin := true // Set this based on your authentication logic
	if !isAdmin {
		http.Redirect(w, r, "/main", http.StatusSeeOther) // Redirect to main page if not admin
		return
	}

	// If user is admin, render admin page
	tmpl, err := template.ParseFiles("admin.html")
	if err != nil {
		log.Fatal("Failed to parse admin template:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		log.Fatal("Failed to execute admin template:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func serveRegistrationPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "registration.html")
}
func serveResetPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "reset_request.html")
}
func renderLoginPage(w http.ResponseWriter, errorMsg, successMsg string) {
	tmpl, err := template.ParseFiles("login.html")
	if err != nil {
		log.Fatal("Failed to parse login template:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		ErrorMsg   string
		SuccessMsg string
	}{
		ErrorMsg:   errorMsg,
		SuccessMsg: successMsg,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Fatal("Failed to execute login template:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func generateConfirmationToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
func handleMain(w http.ResponseWriter, r *http.Request) {
	pageStr := r.FormValue("page")
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}
	prevPage := page - 1
	nextPage := page + 1

	filter := r.FormValue("filter")
	sort := r.FormValue("sort")

	var products []Product
	query := db
	if filter != "" {
		query = query.Where("name LIKE ?", "%"+filter+"%")
	}
	switch sort {
	case "name_asc":
		query = query.Order("name ASC")
	case "name_desc":
		query = query.Order("name DESC")
	case "price_asc":
		query = query.Order("price ASC")
	case "price_desc":
		query = query.Order("price DESC")
	}
	limit := 10
	offset := (page - 1) * limit
	query = query.Limit(limit).Offset(offset)
	if err := query.Find(&products).Error; err != nil {
		log.Error("Failed to fetch products:", err)
		http.Error(w, "Failed to fetch products", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("main.html")
	if err != nil {
		log.Fatal("Failed to parse main template:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Products []Product
		Page     int
		PrevPage int
		NextPage int
		Filter   string
		Sort     string
	}{
		Products: products,
		Page:     page,
		PrevPage: prevPage,
		NextPage: nextPage,
		Filter:   filter,
		Sort:     sort,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Fatal("Failed to execute main template:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func sendConfirmationEmail(email, token string) {
	// Configure the email sender
	sender := gomail.NewMessage()
	sender.SetHeader("From", "mereke61a@gmail.com") // Replace with your email address
	sender.SetHeader("To", email)
	sender.SetHeader("Subject", "Email Confirmation")
	body := fmt.Sprintf("Click the following link to confirm your email: http://localhost:8080/confirm?token=%s", token)
	sender.SetBody("text/html", body)

	// Replace these credentials with your actual email credentials
	dialer := gomail.NewDialer("smtp.gmail.com", 587, "mereke61a@gmail.com", "rire boaf odvl rsmn	")

	// Send the email
	if err := dialer.DialAndSend(sender); err != nil {
		log.Error("Failed to send confirmation email:", err)
		// Handle the error appropriately
	}
}
func handleUpdate(w http.ResponseWriter, r *http.Request) {
	action := r.FormValue("action")
	switch action {
	case "user":
		handleUserUpdate(w, r)
	case "product":
		handleProductUpdate(w, r)
	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
	}
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	action := r.FormValue("action")
	switch action {
	case "user":
		handleUserDelete(w, r)
	case "product":
		handleProductDelete(w, r)
	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
	}
}

func handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.FormValue("userIdUpdate")
	newName := r.FormValue("newName")
	newEmail := r.FormValue("newEmail")

	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid User ID", http.StatusBadRequest)
		return
	}

	var user User
	if err := db.First(&user, userID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if newName != "" {
		user.Name = newName
	}
	if newEmail != "" {
		user.Email = newEmail
	}

	if err := db.Save(&user).Error; err != nil {
		log.Error("Failed to update user:", err)
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}
}

func handleProductUpdate(w http.ResponseWriter, r *http.Request) {
	productIDStr := r.FormValue("productIdUpdate")
	newName := r.FormValue("newName")
	newPriceStr := r.FormValue("newPrice")

	productID, err := strconv.ParseUint(productIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid Product ID", http.StatusBadRequest)
		return
	}

	var updateProduct Product
	result := db.First(&updateProduct, productID)
	if result.Error != nil {
		http.Error(w, "Product not found", http.StatusNotFound)
		return
	}

	if newName != "" {
		updateProduct.Name = newName
	}
	if newPriceStr != "" {
		newPrice, err := strconv.ParseFloat(newPriceStr, 64)
		if err != nil {
			http.Error(w, "Invalid price", http.StatusBadRequest)
			return
		}
		updateProduct.Price = newPrice
	}
	db.Save(&updateProduct)
}

func handleUserDelete(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.FormValue("userIdDelete")

	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid User ID", http.StatusBadRequest)
		return
	}

	var user User
	if err := db.First(&user, userID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if err := db.Delete(&user).Error; err != nil {
		log.Error("Failed to delete user:", err)
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}
}

func handleProductDelete(w http.ResponseWriter, r *http.Request) {
	productIDStr := r.FormValue("productIdDelete")

	productID, err := strconv.ParseUint(productIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid Product ID", http.StatusBadRequest)
		return
	}

	var deleteProduct Product
	result := db.First(&deleteProduct, productID)
	if result.Error != nil {
		http.Error(w, "Product not found", http.StatusNotFound)
		return
	}

	db.Delete(&deleteProduct, productID)
}

func renderTemplate(w http.ResponseWriter, products []Product, users []User, filter, sort string, page int, successMsg, errorMsg string) {
	tmpl, err := template.ParseFiles("registration.html")
	if err != nil {
		log.Fatal("Failed to parse template:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data := struct {
		Products   []Product
		Users      []User
		Filter     string
		Sort       string
		Page       int
		SuccessMsg string
		ErrorMsg   string
	}{
		Products:   products,
		Users:      users,
		Filter:     filter,
		Sort:       sort,
		Page:       page,
		SuccessMsg: successMsg,
		ErrorMsg:   errorMsg,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Fatal("Failed to execute template:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}
