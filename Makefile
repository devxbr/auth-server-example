build:
	go build -o auth-server .

run:
	./auth-server

test:
	go test -v ./...
	
start-docker:
	docker build -t meu-projeto-auth-server .
	docker run -p 8080:8080 meu-projeto-auth-server
