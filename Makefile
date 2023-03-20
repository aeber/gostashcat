lint:
	docker run --rm -it -v "$(shell pwd):/app" -w /app golangci/golangci-lint:v1.44.2 golangci-lint run ./...

test:
	go vet $(shell go list ./... | grep -v /vendor/)
	go test -race $(shell go list ./... | grep -v /vendor/) -cover
