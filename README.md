PROXYPROTO
-------

proxyproto is a lightweight library that helps aged programs deal with proxy-protocol. It supports both IPv4 and IPv6.

Works on Linux and macOS

Why?
----

There are many aged programs that dont support proxy-protocol (esp. closed source programs).
When they are running behind a load-balancer or reserve proxy, it's hard to preserve source IP address.

How PROXYPROTO works?
-------------------

proxyproto intercep the `accept()` proc, and waits for new imcoming connection and listens for proxy-protocol header from upstream proxy (ie HAProxy, NGINX..)

Once header read, proxyproto replace source ip w/ ip provided by upstream proxy.


Installation
------------

```shell
git clone --depth=1 https://github.com/ba0f3/proxyproto.nim.git proxyproto
cd proxyproto
nim c -d:release src/proxyproto
```

Usage
-----

Use directly inside a nim program that accept incoming connections
```nim
import proxyproto
```

For existing programs, use LD_PRELOAD

```shell
$LD_PRELOAD=./src/libproxyproto.so nc -vkl -p 4444
[PROXY] initializing
[PROXY] hook accept OK
listening on [any] 4444 ...

```

Donate
-----

Buy me some beer https://paypal.me/ba0f3