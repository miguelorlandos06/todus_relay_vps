.PHONY: all build run test vet race fmt clean

GO ?= go

all: vet test build

build:
	$(GO) build -trimpath -ldflags="-s -w" -o todus_relay_vps .

run:
	$(GO) run .

test:
	$(GO) test ./...

# race detector: requiere CGO habilitado (CGO_ENABLED=1 por defecto en Linux)
race:
	$(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

clean:
	rm -f todus_relay_vps
	$(GO) clean -testcache
