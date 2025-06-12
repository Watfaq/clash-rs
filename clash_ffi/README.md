## Generate FFI Bindings

To generate the FFI bindings for the Clash library, you need to run the following command:

In the *root* directory of the project, run:

```bash
sh ./clash_ffi/build.sh
```

## Integrate with Xcode

Copy the framework to the Xcode project, for example:

```bash
rm -rf ../ChocLite/Libs/clash-rs-ffi.xcframework && cp -r ./out/clash-rs-ffi.xcframework ../ChocLite/Libs
```

And Sync(copy + paste) the bindings with the Xcode project under `bindings` folder.

