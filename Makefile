all: clean build

build:
	@echo "Building SMTP-VALIDATOR"
	@go build -o SMTP-VALIDATOR *.go

clean:
	@echo "Removing SMTP-VALIDATOR binary"
	rm -rf SMTP-VALIDATOR
