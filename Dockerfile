# Imagen mínima para ejecutar el relay en cualquier host (VPS, contenedor, etc.)
# No es estrictamente necesaria para GitHub Actions (allí se usa go run directamente),
# pero se incluye para despliegues alternativos.

FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
# Build estático, sin dependencias CGO
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/relay .

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /out/relay /relay
USER nonroot:nonroot
ENTRYPOINT ["/relay"]
