postgres: stop-postgres
	docker run -e POSTGRES_DB=coyote -e POSTGRES_HOST_AUTH_METHOD=trust -itd -p 127.0.0.1:5432:5432 --name acmed-postgres postgres:latest

stop-postgres:
	docker rm -f acmed-postgres || :

run-with-backtrace:
	RUST_BACKTRACE=1 rustup run nightly cargo run

.PHONY: postgres stop-postgres
