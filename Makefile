.PHONY: build run clean linux windows

APP := phantom-harvest

build:
	go build -o $(APP) ./cmd/harvest/

run: build
	./$(APP)

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o build/$(APP)_linux_amd64 ./cmd/harvest/

windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o build/$(APP)_windows_amd64.exe ./cmd/harvest/

all: linux windows

clean:
	rm -f $(APP)
	rm -rf build/
