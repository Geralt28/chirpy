package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Geralt28/chirpy/internal/auth"
	"github.com/Geralt28/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	secret         string
	polka_key      string
}

type User struct {
	ID            uuid.UUID `json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Email         string    `json:"email"`
	Is_chirpy_red bool      `json:"is_chirpy_red"`
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

func BadToken(w http.ResponseWriter) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte("Unauthorised user"))
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
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		fmt.Println("error: could not get token from header")
		BadToken(w)
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		BadToken(w)
		return
	}
	fmt.Println("validated user ID which requested posting:", userID)

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
		UserID: userID,
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
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	req := request{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	hashed_pass, err := auth.HashPassword(req.Password)
	if err != nil {
		fmt.Println("error: could not hash password")
		return
	}
	userParams := database.CreateUserParams{
		Email:          req.Email,
		HashedPassword: hashed_pass,
	}
	user_data, err := cfg.db.CreateUser(context.Background(), userParams)
	if err != nil {
		fmt.Println("error: user not created into database")
		http.Error(w, "Could not create user", http.StatusInternalServerError)
		return
	}
	user := User{
		ID:            user_data.ID,
		CreatedAt:     user_data.CreatedAt,
		UpdatedAt:     user_data.UpdatedAt,
		Email:         user_data.Email,
		Is_chirpy_red: user_data.IsChirpyRed,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Password     string `json:"password"`
		Email        string `json:"email"`
		ExpiresInSec int    `json:"expires_in_seconds,omitempty"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fmt.Println("error: could not decode json")
		return
	}
	if req.ExpiresInSec == 0 {
		req.ExpiresInSec = 60
	}

	user, err := cfg.db.GetUser(context.Background(), req.Email)
	if err != nil {
		fmt.Println("error: user could not be find. email:", req.Email)
		return
	}
	err = auth.CheckPasswordHash(req.Password, user.HashedPassword)
	if err != nil {
		fmt.Println("error: wrong password")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Incorrect email or password"))
		return
	}
	w.Header().Set("Content-Type", "application/json")

	type userResponse struct {
		ID            uuid.UUID `json:"id"`
		Created_at    time.Time `json:"created_at"`
		Updated_at    time.Time `json:"updated_at"`
		Email         string    `json:"email"`
		Is_chirpy_red bool      `json:"is_chirpy_red"`
		Token         string    `json:"token"`
		Refresh_Token string    `json:"refresh_token"`
	}
	token, err := auth.MakeJWT(user.ID, cfg.secret, time.Duration(req.ExpiresInSec)*time.Second)
	if err != nil {
		fmt.Println("error: could not generate token")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Could not generate token"))
		return
	}
	refresh_token, err := auth.MakeRefreshToken()
	if err != nil {
		fmt.Println("error: could not generate refresh_token")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	RefreshTokenParams := database.StoreRefreshTokenParams{
		Token:  refresh_token,
		UserID: user.ID,
	}
	savedRefreshToken, err := cfg.db.StoreRefreshToken(context.Background(), RefreshTokenParams)
	if err != nil {
		log.Println("error: could not save RefreshToken into database")
		return
	}
	odpowiedz := userResponse{
		ID:            user.ID,
		Created_at:    user.CreatedAt,
		Updated_at:    user.UpdatedAt,
		Email:         user.Email,
		Is_chirpy_red: user.IsChirpyRed,
		Token:         token,
		Refresh_Token: savedRefreshToken.Token,
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(odpowiedz); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (cfg *apiConfig) handlerRefresh(w http.ResponseWriter, r *http.Request) {
	refresh_token, err := auth.GetRefreshToken(r.Header)
	if err != nil {
		log.Println("error: could not retrieve refresh_token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	ref_token, err := cfg.db.ReadRefreshToken(context.Background(), refresh_token)
	if err != nil || ref_token.RevokedAt.Valid {
		log.Println("error: bad refresh token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// tutaj trzeba jeszcze uzyskac uzytkownika i nowy token, ktory zostanie wyslany - uwaga dodac jeszcze sprawdzenie czy nie expired token (wyzej) bo nie zrobilem tego
	type odp struct {
		Token string `json:"token"`
	}
	newToken, err := auth.MakeJWT(ref_token.UserID, cfg.secret, time.Minute)
	if err != nil {
		log.Println("error: could not generate new token")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	odpowiedz := odp{
		Token: newToken,
	}
	json.NewEncoder(w).Encode(odpowiedz)
}

func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, r *http.Request) {
	refresh_token, err := auth.GetRefreshToken(r.Header)
	if err != nil {
		log.Println("error: could not retrieve refresh_token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	_, err = cfg.db.RevokeRefreshToken(context.Background(), refresh_token)
	if err != nil {
		log.Println("error: could not revoke token, maybe does not exist")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) handlerChangeUser(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("error: could not decode request body (ChangeUser)")
		return
	}
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("error: could not get token from header (ChangeUser)")
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	hashed_pass, err := auth.HashPassword(req.Password)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Println("error: could not hash password")
		return
	}
	userParams := database.UpdateUserParams{
		Email:          req.Email,
		HashedPassword: hashed_pass,
		ID:             userID,
	}
	updUser, err := cfg.db.UpdateUser(context.Background(), userParams)
	if err != nil {
		log.Println("error: could not update user")
		return
	}
	odpowiedz := User{
		ID:            updUser.ID,
		Email:         updUser.Email,
		UpdatedAt:     updUser.UpdatedAt,
		CreatedAt:     updUser.CreatedAt,
		Is_chirpy_red: updUser.IsChirpyRed,
	}
	json.NewEncoder(w).Encode(odpowiedz)
}

func (cfg *apiConfig) handlerDeleteChirp(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("error: could not get token from header (DeleteChirp)")
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	chirpID := r.PathValue("chirpID")
	if chirpID == "" {
		http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
		return
	}
	chirpDB, err := cfg.db.Get1Chirp(context.Background(), uuid.MustParse(chirpID))
	if err != nil {
		log.Println("error: can not find chirp")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if userID != chirpDB.UserID {
		w.WriteHeader(http.StatusForbidden)
		log.Println("error: user can not delete someone others chirp")
		return
	}
	log.Println("deleting chirp:", chirpID, "for user:", userID)
	if err := cfg.db.DeleteChirp(context.Background(), uuid.MustParse(chirpID)); err != nil {
		log.Println("error: could not delete chirp")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) handlerWebHooks(w http.ResponseWriter, r *http.Request) {
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("error: could not get API Key")
		return
	}
	if apiKey != cfg.polka_key {
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("error: not authorised")
		return
	}
	type User_ID_struct struct {
		User_id uuid.UUID `json:"user_id"`
	}
	type WebHooks struct {
		Event string         `json:"event"`
		Data  User_ID_struct `json:"data"`
	}
	var webhooks WebHooks
	if err := json.NewDecoder(r.Body).Decode(&webhooks); err != nil {
		w.WriteHeader(http.StatusBadRequest) // nie jestem pewien ktory request ale lepiej czyms odpowiadac
		log.Println("error: could not decode request")
		return
	}
	defer r.Body.Close()
	if webhooks.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		log.Println("error: missing event 'user.upgraded'")
		return
	}
	upgraded_user, err := cfg.db.UpgradeUser(context.Background(), webhooks.Data.User_id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		log.Println("error: could not upgrade user; user not found")
		return
	}
	log.Println(upgraded_user)
	w.WriteHeader(http.StatusNoContent)
	w.Write([]byte{})
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
	secret := os.Getenv("SECRET")
	polka_key := os.Getenv("POLKA_KEY")
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
		db:        dbQueries,
		platform:  platform,
		secret:    secret,
		polka_key: polka_key,
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
	mux.HandleFunc("POST /api/login", cfg.handlerLogin)
	mux.HandleFunc("POST /api/refresh", cfg.handlerRefresh)
	mux.HandleFunc("POST /api/revoke", cfg.handlerRevoke)
	mux.HandleFunc("PUT /api/users", cfg.handlerChangeUser)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", cfg.handlerDeleteChirp)
	mux.HandleFunc("POST /api/polka/webhooks", cfg.handlerWebHooks)

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
