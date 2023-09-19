# clash-rs
Hello Clash

## Doc

https://watfaq.github.io/clash-rs/clash_doc/

## Usage

```shell
-> % ./target/debug/clash -h
Usage: clash [OPTIONS]

Options:
  -d, --directory <DIRECTORY>
  -c, --config <FILE>          [default: config.yaml]
  -t, --test
  -h, --help                   Print help
  -V, --version                Print version
```

## Access

### SSH

```
Host gitea-ssh.yba.dev
  ProxyCommand /opt/homebrew/bin/cloudflared access ssh --hostname %h
```

### LFS

```
git config --add http.extraheader "cf-access-token: $(cloudflared access token -app=https://gitea.yba.dev)"
```