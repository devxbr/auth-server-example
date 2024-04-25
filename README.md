# OAuth 2.0 Authorization Server with PKCE

Este é um exemplo de implementação de um servidor de autorização OAuth 2.0 com suporte para PKCE (Proof Key for Code Exchange) em Go.

## Introdução

Este servidor de autorização permite que clientes autenticados solicitem tokens de acesso, usando um fluxo de autorização baseado em código. Ele também oferece suporte ao PKCE para garantir a segurança do fluxo de autorização.

## Pré-requisitos

Certifique-se de ter Go instalado em sua máquina antes de prosseguir.

## Instalação

1. Clone este repositório:
   ```bash
   git clone https://github.com/devxbr/auth-server.git


2. Navegue para o repositório clonado:
   ```bash
    cd auth-server

3. Buildar e rodar o servidor
   ```bash
    go build
    ./auth-server

## Rodando no Docker

Se preferir, você pode executar o servidor em um contêiner Docker. Siga as etapas abaixo:

1. Certifique-se de ter o Docker instalado em sua máquina.
2. Clone este repositório:

   ```bash
   git clone https://github.com/devxbr/auth-server.git

3. Navegue até o diretório clonado:
   ```bash
   cd auth-server

4. Construa a imagem Docker do projeto:
   ```bash
   docker build -t auth-server .

5. Execute o contêiner Docker:
   ```bash
   docker run -p 8080:8080 auth-server

## Makefile
O projeto também inclui um Makefile com os seguintes comandos:
    ```bash
    build: Compila o servidor Go.
    ```bash
    run: Executa o servidor Go.
    ```bash
    test: Executa os testes no código Go.
    ```bash
    start-docker: Constrói e executa o servidor em um contêiner Docker.
    
    
    Você pode executar esses comandos na raiz do projeto usando make <comando>.   


## Endereço do servidor

The server will be available at http://localhost:8080.


## Endpoints

- `/oauth2/login`: Endpoint para gerar URL de autorização com PKCE.
- `/oauth2/v1/authorize`: Endpoint para manipular solicitações de autorização.
- `/oauth2/v1/token`: Endpoint para trocar código de autorização por token.
- `/login`: Alias para o endpoint de login.
- Rotas de arquivos estáticos para páginas do frontend: `/auth`, `/auth/auth.html`, `/auth/consent.html`, `/private/dashboard.html`.

## CORS Configuration

O servidor está configurado para aceitar requisições CORS apenas de `http://localhost:8080`.


## Diagrama de Sequência authorization code com PKCE

![Diagrama de Sequência](https://images.ctfassets.net/cdy7uua7fh8z/3pstjSYx3YNSiJQnwKZvm5/33c941faf2e0c434a9ab1f0f3a06e13a/auth-sequence-auth-code-pkce.png)

### Contribuição
Contribuições são bem-vindas! Se encontrar um problema ou tiver alguma sugestão de melhoria, sinta-se à vontade para abrir uma issue ou enviar um pull request.

### Licença
Este projeto está licenciado sob a Licença MIT. Consulte o arquivo LICENSE para obter detalhes.