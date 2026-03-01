verify:
  cargo run -p clash-rs -- -t

run:
  cargo run -p clash-rs --profile detailed-release --features=standard -- -c config.yaml

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
  cargo build -p clash-rs --profile detailed-release --features=standard
  rm -f "C:\Program Files\Clash Verge\verge-mihomo-alpha.exe"
  rm -rf "C:\Users\iHsin\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev\logs"
  cp target/release/clash-rs.exe "C:\Program Files\Clash Verge\verge-mihomo-alpha.exe"

test-proxy:
  curl -x socks5h://127.0.0.1:7890 https://www.google.com