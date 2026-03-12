FROM golang:1.24 AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/pdpd ./cmd/pdpd
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/migrate ./cmd/migrate

FROM gcr.io/distroless/base-debian12
WORKDIR /app

COPY --from=builder /out/pdpd /usr/local/bin/pdpd
COPY --from=builder /out/migrate /usr/local/bin/migrate

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/pdpd"]
