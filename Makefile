.PHONY: build test fmt vet bench clean

GO ?= go
BIN := bin

build: $(BIN)/scdlp-agent $(BIN)/scdlp

$(BIN)/scdlp-agent: $(shell find . -name '*.go' -not -path './e2e/*')
	@mkdir -p $(BIN)
	$(GO) build -o $@ ./cmd/scdlp-agent

$(BIN)/scdlp: $(shell find . -name '*.go' -not -path './e2e/*')
	@mkdir -p $(BIN)
	$(GO) build -o $@ ./cmd/scdlp

test:
	$(GO) test ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

bench:
	$(GO) test -bench=. -benchmem ./internal/agent/...

clean:
	rm -rf $(BIN)

# --- ESF bundle targets -------------------------------------------------------

SIGN_ID ?= -
TEAM_ID ?= UNSIGNED

extension:
	SCDLP_SIGN_ID="$(SIGN_ID)" SCDLP_TEAM_ID="$(TEAM_ID)" ./extension/build.sh

host: extension
	SCDLP_SIGN_ID="$(SIGN_ID)" ./host/build.sh

bundle: host

activate: bundle
	./dist/scdlp.app/Contents/MacOS/scdlp-host activate

deactivate:
	./dist/scdlp.app/Contents/MacOS/scdlp-host deactivate

.PHONY: extension host bundle activate deactivate
