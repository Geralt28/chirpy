package main

import (
	"fmt"
	"net/http"
)

func readinessHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "text/plain; charset=utf-8") //ustawianie headera odpowiedzi
	res.WriteHeader(http.StatusOK)                                // ustawianie status code
	res.Write([]byte("OK"))                                       //pisanie body odpowiedzi - musi byc jako Write([]byte) (int, error)

}

func main() {
	mux := http.NewServeMux()
	filePath := "/home/geralt/workspace/github.com/Geralt28/chirpy"
	port := "8080"

	mux.HandleFunc("/healthz", readinessHandler)
	mux.Handle("/app/", http.StripPrefix("/app", http.FileServer(http.Dir(filePath+"/app"))))

	//mux.Handle("/", http.FileServer(http.Dir(filePath)))

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
