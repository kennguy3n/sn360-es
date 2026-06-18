# syntax=docker/dockerfile:1.7

# Pin to a specific Go patch + Alpine version rather than the
# floating golang:1.25-alpine tag. Floating tags repoint over time
# (Alpine 3.22 -> 3.23, Go 1.25.11 -> 1.25.12, …), which means an
# image rebuild months from now can land on a newer toolchain or a
# different Alpine major and quietly change behaviour. Pinning keeps
# CI / prod builds bit-identical for the lifetime of this commit;
# Renovate / Dependabot bump the pin via an explicit PR.
FROM golang:1.25.11-alpine3.22 AS builder
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
