package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
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
}

func (cfg *apiConfig) handlerValidateChirp(w http.ResponseWriter, r *http.Request) {

	type request struct {
		Body string `json:"body"`
	}
	type errorResponse struct {
		Error string `json:"error"`
	}
	type successResponse struct {
		Valid bool `json:"valid"`
	}

	w.Header().Add("Content-Type", "application/json") //naglowek taki sam dla wszystkich odpowiedzi

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest) //status 400, checked on net - not sure which is "right" code
		//odpowiedz, _ := json.Marshal((map[string]string{"error": "Something went wrong"}))
		//w.Write(odpowiedz)
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
	w.WriteHeader(http.StatusOK) //status 200
	json.NewEncoder(w).Encode(successResponse{Valid: true})
	return
}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8") //ustawianie headera odpowiedzi
	w.WriteHeader(http.StatusOK)                                // ustawianie status code
	w.Write([]byte(http.StatusText(http.StatusOK)))             //pisanie body odpowiedzi - musi byc jako Write([]byte) (int, error)
	//w.Write([]byte("OK"))
}

func main() {
	mux := http.NewServeMux()
	filePath := "/home/geralt/workspace/github.com/Geralt28/chirpy"
	port := "8080"

	//mux.Handle("/app/", http.StripPrefix("/app", http.FileServer(http.Dir(filePath+"/app"))))
	cfg := &apiConfig{}
	mux.Handle("/app/", cfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(filePath+"/app")))))
	mux.HandleFunc("GET /api/healthz", readinessHandler)
	//mux.HandleFunc("GET /api/metrics", cfg.handlerMetrics)
	//mux.HandleFunc("POST /api/reset", cfg.handlerReset)
	// revers to upper lines to pass -3.1, below it is for lesson 3.4 (both will not work)
	mux.HandleFunc("GET /admin/metrics", cfg.handlerMetrics)
	mux.HandleFunc("POST /admin/reset", cfg.handlerReset)
	mux.HandleFunc("POST /api/validate_chirp", cfg.handlerValidateChirp)

	server := &http.Server{
		Addr:    ":" + port, // Bind to port 8080
		Handler: mux,        // mux as a handler
	}

	// Start the server
	fmt.Println("Starting server on http://localhost:8080")
	fmt.Printf("Serving files from %s on port: %s\n", filePath, port)
	err := server.ListenAndServe()
	if err != nil {
		fmt.Println("Error starting server:", err)
	}
}
