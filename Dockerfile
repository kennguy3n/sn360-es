# syntax=docker/dockerfile:1.7

FROM golang:1.25-alpine AS builder
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
WORKDIR /src

COPY go.mod go.sum* ./
RUN go mod download || true

COPY . .

RUN go build -trimpath -ldflags="-s -w" -o /out/sn360-es ./cmd/sn360-es

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /out/sn360-es /app/sn360-es

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/sn360-es"]
