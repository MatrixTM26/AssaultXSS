build:
	go mod tidy && go build -o assaultxss ./cmd/main.go

android:
	GOOS=linux GOARCH=arm64 go build -o assaultxss-arm64 ./cmd/main.go

clean:
	rm -f assaultxss assaultxss-arm64

run:
	go run ./cmd/main.go -h
