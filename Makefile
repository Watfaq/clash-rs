.PHONY: docs
docs:
	@rm -rf ./docs
	@cargo doc -p clash_doc --no-deps
	@echo "<meta http-equiv=\"refresh\" content=\"0; url=clash_doc\">" > target/doc/index.html
	@cp -r target/doc ./docs
