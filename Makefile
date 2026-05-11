build:
	cargo build
	sudo setcap cap_net_raw+ep ./target/debug/gannet

release:
	cargo build --release
	sudo setcap cap_net_raw+ep ./target/release/gannet