[ ! -d "target/artifacts" ] && mkdir target/artifacts

for TARGET in $1; do
  echo "building for $TARGET"
  rustup target add $TARGET
  cargo build -p clash --target $TARGET --release
  mv ./target/$TARGET/release/clash ./target/artifacts/clash-$TARGET
done
