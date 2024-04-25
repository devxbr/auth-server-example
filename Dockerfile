FROM golang:latest
WORKDIR /app
COPY . .
RUN go build -o auth-server .
EXPOSE 8080
CMD ["./auth-server"]
