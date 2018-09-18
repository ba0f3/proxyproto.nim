LIBPROXY
-------

libproxy is a lightweight library that helps aged programs can deal with proxy-protocol.

Why?
----

There are many aged programs that dont support proxy-protocol (esp. closed source programs).
When they are running behind a load-balancer or reserve proxy, it's hard to preserve source IP address.

How LIBPROXY works?
-------------------

libproxy intercep the `accept()` proc, and waits for new imcoming connection and listens for proxy-protocol header from upstream proxy (ie HAProxy, NGINX..)

Once header read, libproxy replace source ip w/ ip provided by upstream proxy.

Requirements
------------

- Nim compiler
- Nimble package manager
- Subhook package (`nimble install subhook`)


Installation
------------

```shell
git clone --depth=1 https://github.com/ba0f3/libproxy.nim.git libproxy
cd libproxy
nim c -d:release src/proxy

```

Usage
-----

Just add `src/libproxy.so` to `LD_PRELOAD`

```shell
$LD_PRELOAD=./src/libproxy.so nc -vkl -p 4444
[PROXY] initializing
[PROXY] hook accept OK
listening on [any] 4444 ...

```

Donate
-----

Buy me some beer https://paypal.me/ba0f3