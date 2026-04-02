.PHONY: build run clean linux windows all garble-linux garble-windows garble-all

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

## Garble builds (fully obfuscated — install: go install mvdan.cc/garble@latest)
garble-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 garble -literals -tiny build -o build/$(APP)_linux_amd64 ./cmd/harvest/

garble-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 garble -literals -tiny build -o build/$(APP)_windows_amd64.exe ./cmd/harvest/

garble-all: garble-linux garble-windows

clean:
	rm -f $(APP)
	rm -rf build/
