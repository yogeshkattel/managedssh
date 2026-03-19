APP := managedssh

.PHONY: help build run test fmt tidy install clean

help:
	@printf "Available targets:\n"
	@printf "  make build    Build the binary\n"
	@printf "  make run      Run the app\n"
	@printf "  make test     Run tests\n"
	@printf "  make fmt      Format Go files\n"
	@printf "  make tidy     Tidy Go modules\n"
	@printf "  make install  Install the binary to GOPATH/bin\n"
	@printf "  make clean    Remove the built binary\n"

build:
	go build -o $(APP) .

run:
	go run .

test:
	go test ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

tidy:
	go mod tidy

install:
	go install .

clean:
	rm -f $(APP)
