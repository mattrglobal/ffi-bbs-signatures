CC = gcc

build: rust

test:
	@${CC} tests/bbs_test.c -o bbs_test -Iinclude -Ltarget/release -lbbs
	@chmod +x bbs_test
	@./bbs_test
rust:
	@cargo build --release
clean:
	@cargo clean
	@rm -rf target
	@rm -f bbs_test