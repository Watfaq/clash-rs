verify:
  cargo run -p clash-rs -- -t

run:
  cargo run -p clash-rs -- -c config.yaml

fmt:
  cargo +nightly fmt

docs:
  rm -rf ./docs
  cargo doc -p clash-doc --no-deps
  echo '<meta http-equiv="refresh" content="0; url=clash_doc">' > target/doc/index.html
  cp -r target/doc ./docs

test-no-docker:
  CLASH_RS_CI=true cargo test --all --all-features

verge:
  cargo build -p clash-rs --release --features=standard
  rm -f "C:\Program Files\Clash Verge\verge-mihomo-alpha.exe"
  cp target/release/clash-rs.exe "C:\Program Files\Clash Verge\verge-mihomo-alpha.exe"