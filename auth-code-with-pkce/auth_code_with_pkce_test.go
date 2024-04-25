package authcodewithpkce

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoginHandler(t *testing.T) {
	// Definido o contrato da requisição
	reqBody := AuthenticationRequest{
		ClientID:    "dxFPB5dj1bX6WQKDo_lF0KIM",
		RedirectURI: "http://localhost:8080/auth/consent.html",
		Scope:       "read write",
		State:       "xyz",
		Email:       "user@example.com",
		Password:    "password123",
	}

	reqBodyBytes, _ := json.Marshal(reqBody)

	// Definido o endpoint da requisição
	req, err := http.NewRequest("POST", "/oauth2/v1/authorize", bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	// Definido o nome da função de login
	handler := http.HandlerFunc(LoginHandler)

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Expected status code %d; got %d", http.StatusFound, rr.Code)
	}
}

func TestGenerateAuthorizationURLWithPKCE(t *testing.T) {
	// Definido o endpoint da requisição
	req, err := http.NewRequest("GET", "/oauth2/login?client_id=dxFPB5dj1bX6WQKDo_lF0KIM&redirect_uri=http://localhost:8080/auth/consent.html&scope=read%20write&state=xyz&code_verifier=12345678&code_challenge=abcdefgh&code_challenge_method=S256", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	//Definido o nome da função que retorna a url de autorização
	handler := http.HandlerFunc(GenerateAuthorizationURLWithPKCE)

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Expected status code %d; got %d", http.StatusFound, rr.Code)
	}
}
