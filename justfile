verify:
  cargo run -p clash-rs -- -t

docs:
  rm -rf ./docs
  cargo doc -p clash-doc --no-deps
  echo '<meta http-equiv="refresh" content="0; url=clash-doc">' > target/doc/index.html
  cp -r target/doc ./docs

test-no-docker:
  CLASH_RS_CI=true cargo test --all --all-features