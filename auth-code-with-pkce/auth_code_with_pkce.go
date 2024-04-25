package authcodewithpkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

// AuthorizationCodeStore é uma estrutura de armazenamento para códigos de autorização temporários
var AuthorizationCodeStore = make(map[string]*AuthorizationRequest)

// Client representa um cliente registrado
type Client struct {
	ID          string
	RedirectURI []string
}

// ClientStore é uma estrutura de armazenamento para clientes registrados
var ClientStore = map[string]*Client{
	"dxFPB5dj1bX6WQKDo_lF0KIM": {
		ID:          "dxFPB5dj1bX6WQKDo_lF0KIM",
		RedirectURI: []string{"http://localhost:8080/auth/consent.html", "http://localhost:8080/private/dashboard.html"},
	},
}

// AuthorizationRequest representa uma solicitação de autorização
type AuthorizationRequest struct {
	ClientID     string
	RedirectURI  string
	State        string
	CodeVerifier string
}

// Definindo uma estrutura para os dados JSON
type AuthenticationRequest struct {
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri"`
	Scope         string `json:"scope"`
	ResponseType  string `json:"response_type"`
	State         string `json:"state"`
	Email         string `json:"email"`
	Password      string `json:"password"`
	CodeChallenge string `json:"code_challenge"`
	CodeVerifier  string `json:"code_verifier"`
}

// TokenRequest representa uma solicitação de troca de auth code por token
type TokenRequest struct {
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	State        string `json:"state"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	GrantType    string `json:"grant_type"`
}

// generateAuthorizationCode gera um código de autorização
func generateAuthorizationCode() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // Tratar melhor o erro aqui, talvez logar e retornar um erro HTTP 500
	}
	return base64.URLEncoding.EncodeToString(b)
}

// generateCodeChallenge calcula o code challenge usando o code verifier
func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// isRedirectURIValid verifica se a URI de redirecionamento é válida
func isRedirectURIValid(client *Client, redirectURI string) bool {
	if strings.Contains(redirectURI, "/auth/auth.html") {
		return true
	}

	for _, uri := range client.RedirectURI {
		if uri == redirectURI {
			return true
		}
	}
	return false
}

// LoginHandler manipula a solicitação de login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var data AuthenticationRequest
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	if data.Email == "" || data.Password == "" {
		http.Error(w, "Credenciais inválidas", http.StatusUnauthorized)
		return
	}

	if data.RedirectURI == "" {
		http.Error(w, "URI de redirecionamento inválida", http.StatusUnauthorized)
		return
	}

	if data.ClientID == "" {
		http.Error(w, "ID do cliente inválido", http.StatusUnauthorized)
		return
	}

	// Gera um código de autorização
	code := generateAuthorizationCode()
	AuthorizationCodeStore[code] = &AuthorizationRequest{ClientID: data.ClientID, RedirectURI: data.RedirectURI, State: data.State}

	encodedScope := url.QueryEscape(data.Scope)

	callbackURL := fmt.Sprintf("%s?code=%s&redirect_uri=%s&client_id=%s&state=%s&code_challenge=%s&code_challenge_method=%s&scope=%s",
		data.RedirectURI, code, "http://localhost:8080/private/dashboard.html", data.ClientID, data.State, data.CodeChallenge, "S256", encodedScope)
	http.Redirect(w, r, callbackURL, http.StatusFound)
}

// GenerateAuthorizationURLWithPKCE gera uma URL de autorização com PKCE
func GenerateAuthorizationURLWithPKCE(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	codeVerifier := r.URL.Query().Get("code_verifier")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	sha2 := sha256.New()
	io.WriteString(sha2, codeVerifier)
	calculatedCodeChallenge := base64.RawURLEncoding.EncodeToString(sha2.Sum(nil))

	if calculatedCodeChallenge != generateCodeChallenge(codeVerifier) {
		http.Error(w, "Código de desafio inválido", http.StatusUnauthorized)
		return
	}

	client, ok := ClientStore[clientID]
	if !ok || !isRedirectURIValid(client, redirectURI) {
		http.Error(w, "Cliente não autorizado", http.StatusUnauthorized)
		return
	}

	// Redireciona de volta para o cliente com o código de autorização e o estado
	callbackURL := fmt.Sprintf("%s?response_type=code&client_id=%s&state=%s&code_challenge=%s&code_challenge_method=%s&scope=%s",
		redirectURI, clientID, state, codeChallenge, codeChallengeMethod, scope)
	http.Redirect(w, r, callbackURL, http.StatusFound)
}

// TokenHandler manipula a solicitação de token
func TokenHandler(w http.ResponseWriter, r *http.Request) {
	var data TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	client, ok := ClientStore[data.ClientID]
	if !ok {
		http.Error(w, "Cliente não autorizado", http.StatusUnauthorized)
		return
	}

	// Verifica se o código de autorização está presente e válido
	authReq, ok := AuthorizationCodeStore[data.Code]
	if !ok || authReq.ClientID != client.ID {
		http.Error(w, "Código de autorização inválido", http.StatusUnauthorized)
		return
	}

	// Verifica se o estado corresponde
	if data.State != authReq.State {
		http.Error(w, "Estado inválido", http.StatusUnauthorized)
		return
	}

	// Define as informações do token
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = data.ClientID
	claims["exp"] = time.Now().Add(time.Minute * 1).Unix()

	// Assina o token com uma chave secreta
	tokenString, err := token.SignedString([]byte("chave_secreta"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, tokenString)
}
