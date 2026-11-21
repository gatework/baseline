# Shared gates come from the published go-standards; see standard.mk.
include standard.mk

CHECK_EXTRA := modverify

.PHONY: modverify build corpus fuzz
modverify:
	$(GO) mod verify

build:
	$(GO) build -o bin/baseline ./cmd/baseline

# Private corpus: real configuration backups kept outside the repository.
corpus:
	BASELINE_CORPUS="$(BASELINE_CORPUS)" $(GO) test -count=1 -run '^TestPrivateCorpus$$' -v ./internal/workflow

fuzz:
	$(GO) test -run '^$$' -fuzz FuzzExtract -fuzztime 30s ./vendors/comware
	$(GO) test -run '^$$' -fuzz FuzzExtract -fuzztime 30s ./vendors/nxos
	$(GO) test -run '^$$' -fuzz FuzzExtract -fuzztime 30s ./vendors/ios
