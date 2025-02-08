FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY ./src/go.mod ./src/go.sum ./
RUN go mod download

COPY src/ .

RUN GOOS=linux go build -o backend .

FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/backend .

CMD ["./backend"]
