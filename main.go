package main

import (
	"fmt"
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
	w.Write([]byte(fmt.Sprintf("Hits: %d", cfg.fileserverHits.Load())))
}

func (cfg *apiConfig) handlerReset(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset to 0"))
}

func readinessHandler(w http.ResponseWriter, rr *http.Request) {
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
	mux.HandleFunc("GET /api/metrics", cfg.handlerMetrics)
	mux.HandleFunc("POST /api/reset", cfg.handlerReset)
	//mux.Handle("GET /metrics", cfg.numberServerHits(http.StripPrefix("/metrics", http.FileServer(http.Dir(filePath+"/metrics")))))
	//mux.Handle("POST /reset", cfg.resetServerHits(http.StripPrefix("/reset", http.FileServer(http.Dir(filePath+"/reset")))))
	//mux.Handle("/", cfg.middlewareMetricsInc(http.StripPrefix("/", http.FileServer(http.Dir(filePath+"/app")))))

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
