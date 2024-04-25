package main

import (
	"fmt"
	"net/http"

	authcodewithpkce "github.com/devxbr/auth-server-example/auth-code-with-pkce"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

type HttpServer struct {
	router *mux.Router
}

func NewHttpServer() *HttpServer {
	return &HttpServer{
		router: mux.NewRouter(),
	}
}

func (h *HttpServer) setupRoutes() {
	// Rota para OPTIONS
	h.router.HandleFunc("/cors", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Roteamento para endpoints de autenticação
	h.router.HandleFunc("/oauth2/login", authcodewithpkce.GenerateAuthorizationURLWithPKCE).Methods("GET")
	h.router.HandleFunc("/oauth2/v1/authorize", authcodewithpkce.LoginHandler).Methods("POST")
	h.router.HandleFunc("/oauth2/v1/token", authcodewithpkce.TokenHandler).Methods("POST")
	h.router.HandleFunc("/login", authcodewithpkce.LoginHandler).Methods("POST")

	// Roteamento para endpoints do frontend
	h.router.HandleFunc("/auth", serveStaticFile("./static/index.html")).Methods("GET")
	h.router.HandleFunc("/auth/auth.html", serveStaticFile("./static/auth.html")).Methods("GET")
	h.router.HandleFunc("/auth/consent.html", serveStaticFile("./static/consent.html")).Methods("GET")
	h.router.HandleFunc("/private/dashboard.html", serveStaticFile("./static/dashboard.html")).Methods("GET")
}

func (h *HttpServer) StartHttpServer() {
	h.setupRoutes()

	// Configuração do CORS
	corsHandler := handlers.CORS(
		handlers.AllowedOrigins([]string{"http://localhost:8080"}),
		handlers.AllowedMethods([]string{"GET", "POST", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}),
	)

	// Inicia o servidor na porta 8080
	port := ":8080"
	fmt.Printf("Server hostname...: http://localhost%s\n", port)

	err := http.ListenAndServe(port, corsHandler(h.router))
	if err != nil {
		fmt.Printf("Erro ao iniciar o servidor: %s\n", err)
	}
}

func serveStaticFile(filepath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath)
	}
}
