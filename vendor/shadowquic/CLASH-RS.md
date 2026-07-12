# Vendored ShadowQUIC

This directory is based on commit
`1db0142b3d960d876d5884277edaa210e318965e` from
<https://github.com/spongebob888/shadowquic>.

The clash-rs integration adds `SunnyQuicServer::new_without_user_api`. It keeps
normal SunnyQUIC authentication unchanged while omitting the optional user
management implementation. Consequently, usernames beginning with `admin` are
ordinary proxy users and cannot access user-management operations.
