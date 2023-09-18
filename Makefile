docs:
	cargo doc -p clash_doc --no-deps
	rm -rf ./docs
	echo "<meta http-equiv=\"refresh\" content=\"0; url=build_wheel\">" > target/doc/index.html
	cp -r target/doc ./docs
