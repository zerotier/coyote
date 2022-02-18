postgres: stop-postgres
	docker run -e POSTGRES_DB=coyote -e POSTGRES_HOST_AUTH_METHOD=trust -itd -p 127.0.0.1:5432:5432 --name acmed-postgres postgres:latest

stop-postgres:
	docker rm -f acmed-postgres || :

CARGO_TEST=cargo test -- --test-threads $$(($$(nproc) / 2))

test:
	${CARGO_TEST}

debug-test:
	DEBUG=1 cargo test -- --nocapture --test-threads $$(($$(nproc) / 2))

.PHONY: postgres stop-postgres
