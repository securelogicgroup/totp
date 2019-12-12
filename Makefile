.PHONY: test

test:
	golint
	go vet
	go test