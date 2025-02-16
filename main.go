package main

import (
	"fmt"
	"net/http"
)

func main() {
	mux := http.NewServeMux()

	server := &http.Server{
		Addr:    ":8080", // Bind to port 8080
		Handler: mux,     // mux as a handler
	}

	mux.Handle("/", http.FileServer(http.Dir("/home/geralt/workspace/github.com/Geralt28/chirpy")))

	// Start the server
	fmt.Println("Starting server on http://localhost:8080")
	err := server.ListenAndServe()
	if err != nil {
		fmt.Println("Error starting server:", err)
	}

}
