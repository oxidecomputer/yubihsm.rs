# yubihsm-client.rs

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![MIT/Apache2 licensed][license-image]

[crate-image]: https://img.shields.io/crates/v/yubihsm-client.svg
[crate-link]: https://crates.io/crates/yubihsm-client
[docs-image]: https://docs.rs/yubihsm-client/badge.svg
[docs-link]: https://docs.rs/yubihsm-client/
[build-image]: https://secure.travis-ci.org/tarcieri/yubihsm-client.svg?branch=master
[build-link]: https://travis-ci.org/tarcieri/yubihsm-client
[license-image]: https://img.shields.io/badge/license-MIT/Apache2.0-blue.svg

An experimental pure Rust reimplementation of [libyubihsm] providing an
interface to [YubiHSM2] devices from [Yubico].

[libyubihsm]: https://developers.yubico.com/YubiHSM2/Component_Reference/libyubihsm/
[YubiHSM2]: https://www.yubico.com/products/yubihsm/
[Yubico]: https://www.yubico.com/

## About

This library attempts to reimplement some of the functionality of **libyubihsm**,
a closed-source C library which acts as a libcurl-based HTTP(S) client and sends
commands to the [yubihsm-connector] process, which implements an HTTP(S) server
which sends the commands to the YubiHSM2 hardware device over USB. However,
**libyubihsm** can be difficult to work with because it is shipped as a
platform-specific dynamic library which needs its own special versions of
libcurl and OpenSSL.

**yubihsm-client** is a pure-Rust reimplementation of a similar HTTP(S) client
library for **yubihsm-connector** based on documentation provided by Yubico.
Only a small amount of the functionality provided by **libyubihsm** has been
reimplemented.

**yubihsm-client** is implemented using the [reqwest] Rust HTTP client library.

[yubihsm-connector]: https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/
[reqwest]: https://github.com/seanmonstar/reqwest

## Status

Not ready. Nascent. Do not attempt to use.

## Testing

Tests for **yubihsm-client** assume you have a YubiHSM2 hardware device, have
downloaded the [YubiHSM2 SDK] for your platform, and are running a
**yubihsm-connector** process listening on localhost on the default port of 12345.
The YubiHSM2 device should be in the default factory state. To reset it to this
state, either use the [yubihsm-shell reset] command or press on the YubiHSM2 for
10 seconds immediately after inserting it.

[YubiHSM2 SDK]: https://developers.yubico.com/YubiHSM2/Releases/
[yubihsm-shell reset]: https://developers.yubico.com/YubiHSM2/Commands/Reset.html

## License

**yubihsm-client** is distributed under the terms of both the MIT license and
the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
