.PHONY: build
build:
	./scripts/build.sh

.PHONY: image
image:
	./scripts/image.sh

.PHONY: cert
cert:
	./scripts/cert.sh

.PHONY: test
test:
	./scripts/test.sh

.PHONY: clean
clean:
	./scripts/clean.sh
