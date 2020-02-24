# ecies-ed25519
![checks](https://github.com/phayes/ecies-ed25519/workflows/checks/badge.svg)

ECIES on Twisted Edwards Curve25519 using AEAD / AES-GCM

It uses the excellent [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek) library for ECC operations, 
and provides two different backends for HKDF and AEAD / AES-GCM operations. 

1. The `ring` backend (default) uses [ring](https://github.com/briansmith/ring).  It uses rock solid primitives based on 
BoringSSL, but cannot run on all platforms. For example it won't work on WASM.

2. The `pure_rust` backend. It uses a collection of pure-rust implementations of SHA2, HKDF, AES, and AEAD, which will work
on all platforms. However, some of these implementations haven't been throughly reviewed. To activate this backend add this to
your Cargo.toml file: ` ecies-ed25519 = { version = "0.1", features=["pure_rust"] }`.

