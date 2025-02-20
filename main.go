package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Geralt28/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	htmlResponse := fmt.Sprintf(`<!DOCTYPE html>
	<html>
	  <body>
		<h1>Welcome, Chirpy Admin</h1>
		<p>Chirpy has been visited %d times!</p>
	  </body>
	</html>`, cfg.fileserverHits.Load())
	w.Write([]byte(htmlResponse))
	//w.Write([]byte(fmt.Sprintf("Hits: %d", cfg.fileserverHits.Load())))
}

func (cfg *apiConfig) handlerReset(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset to 0"))
	cfg.db.DeleteUsers(context.Background())
}

func (cfg *apiConfig) handlerPostChirps(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Body    string    `json:"body"`
		User_id uuid.UUID `json:"user_id"`
	}
	type errorResponse struct {
		Error string `json:"error"`
	}
	//type successResponse struct {
	//	Valid bool `json:"valid"`
	//}
	//type successCleaned struct {
	//	Cleaned_body string `json:"cleaned_body"`
	//}
	w.Header().Add("Content-Type", "application/json") //naglowek taki sam dla wszystkich odpowiedzi
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest) //status 400, checked on net - not sure which is "right" code
		json.NewEncoder(w).Encode(errorResponse{Error: "Something went wrong"})
		return
	}
	defer r.Body.Close()
	var req request
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse{Error: "Something went wrong"})
		return
	}
	if len(req.Body) > 140 {
		w.WriteHeader(http.StatusBadRequest) //status 400, checked on net
		json.NewEncoder(w).Encode(errorResponse{Error: "Chirp is too long"})
		return
	}
	//w.WriteHeader(http.StatusOK) //status 200
	// ***** to trzeba odblokowac do zadania 4.2, a pozniej nizej uzyc tego kolejnego *****
	//json.NewEncoder(w).Encode(successResponse{Valid: true})
	slowa := strings.Split(req.Body, " ")
	brzydkie_slowa := map[string]struct{}{
		"kerfuffle": {},
		"sharbert":  {},
		"fornax":    {},
	}
	for i, slowo := range slowa {
		if _, exists := brzydkie_slowa[strings.ToLower(slowo)]; exists {
			slowa[i] = "****"
		}
	}
	chirp_text := strings.Join(slowa, " ")

	//_, err = cfg.db.GetUserByID(context.Background(), userID)
	//if err != nil {
	//w.WriteHeader(http.StatusBadRequest)
	//json.NewEncoder(w).Encode(errorResponse{Error: "User does not exist"})
	//return
	//}

	chirpParams := database.WriteChirpParams{
		Body:   chirp_text,
		UserID: req.User_id,
	}

	type chirpResponse struct {
		ID        uuid.UUID `json:"id"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
		CreatedAt time.Time `json:"created_at"`
	}

	chirp_baza, err := cfg.db.WriteChirp(context.Background(), chirpParams)
	if err != nil {
		debugMsg := fmt.Sprintf("Database error: %v", err) // Convert error to string
		fmt.Println(debugMsg)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errorResponse{Error: debugMsg})
		return
	}

	response := chirpResponse{
		ID:        chirp_baza.ID,
		Body:      chirp_baza.Body,
		UserID:    chirp_baza.UserID,
		CreatedAt: chirp_baza.CreatedAt,
	}

	w.WriteHeader(http.StatusCreated) // Status 201 for successful resource creation
	json.NewEncoder(w).Encode(response)
}

func (cfg *apiConfig) handlerGetChirps(w http.ResponseWriter, r *http.Request) {
	chirps, err := cfg.db.GetChirps(context.Background())
	if err != nil {
		fmt.Println("error: could not get chirps")
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(chirps)
}

func (cfg *apiConfig) handlerGet1Chirp(w http.ResponseWriter, r *http.Request) {
	//fmt.Println("Full URL Path:", r.URL.Path) // Debugging: full request path?
	chirpID := r.PathValue("chirpID")
	//fmt.Println("Extracted chirpID:", chirpID) // Debugging

	if chirpID == "" {
		http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
		return
	}
	fmt.Println(chirpID)
	chirpUUID, err := uuid.Parse(chirpID)
	if err != nil {
		http.Error(w, "Invalid chirp ID format", http.StatusBadRequest)
		return
	}
	chirp, err := cfg.db.Get1Chirp(r.Context(), chirpUUID)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := map[string]interface{}{
		"id":         chirp.ID,
		"body":       chirp.Body,
		"user_id":    chirp.UserID,
		"created_at": chirp.CreatedAt,
	}
	json.NewEncoder(w).Encode(response)
}

func (cfg *apiConfig) handlerCreateUser(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Email string `json:"email"`
	}
	req := request{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	user_data, err := cfg.db.CreateUser(context.Background(), req.Email)
	if err != nil {
		fmt.Println("error: user not created into database")
		http.Error(w, "Could not create user", http.StatusInternalServerError)
		return
	}

	user := User{
		ID:        user_data.ID,
		CreatedAt: user_data.CreatedAt,
		UpdatedAt: user_data.UpdatedAt,
		Email:     user_data.Email,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8") //ustawianie headera odpowiedzi
	w.WriteHeader(http.StatusOK)                                // ustawianie status code
	w.Write([]byte(http.StatusText(http.StatusOK)))             //pisanie body odpowiedzi - musi byc jako Write([]byte) (int, error)
	//w.Write([]byte("OK"))
}

func main() {
	//zaladuj .env
	godotenv.Load()
	// odczytaj link do bazy
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	// otworz polaczenie z baza
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Println("error: can not open database")
		return
	}
	dbQueries := database.New(db)

	//user, err := cfg.db.CreateUser(r.Context(), params.Email)

	mux := http.NewServeMux()
	filePath := "/home/geralt/workspace/github.com/Geralt28/chirpy"
	port := "8080"

	//mux.Handle("/app/", http.StripPrefix("/app", http.FileServer(http.Dir(filePath+"/app"))))

	// Initialize apiConfig with PLATFORM and database queries
	cfg := &apiConfig{
		db:       dbQueries,
		platform: platform,
	}

	mux.Handle("/app/", cfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(filePath+"/app")))))
	mux.HandleFunc("GET /api/healthz", readinessHandler)
	//mux.HandleFunc("GET /api/metrics", cfg.handlerMetrics)
	//mux.HandleFunc("POST /api/reset", cfg.handlerReset)
	// revers to upper lines to pass -3.1, below it is for lesson 3.4 (both will not work)
	mux.HandleFunc("GET /admin/metrics", cfg.handlerMetrics)
	mux.HandleFunc("POST /admin/reset", cfg.handlerReset)
	//mux.HandleFunc("POST /api/validate_chirp", cfg.handlerValidateChirp)
	mux.HandleFunc("POST /api/users", cfg.handlerCreateUser)
	mux.HandleFunc("POST /api/chirps", cfg.handlerPostChirps)
	mux.HandleFunc("GET /api/chirps", cfg.handlerGetChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", cfg.handlerGet1Chirp)

	server := &http.Server{
		Addr:    ":" + port, // Bind to port 8080
		Handler: mux,        // mux as a handler
	}

	// Start the server
	fmt.Println("Starting server on http://localhost:8080")
	fmt.Printf("Serving files from %s on port: %s\n", filePath, port)
	err = server.ListenAndServe()
	if err != nil {
		fmt.Println("Error starting server:", err)
	}
}
