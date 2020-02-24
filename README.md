# ecies-ed25519
[![docs](https://docs.rs/ecies-ed25519/badge.svg)](https://docs.rs/ecies-ed25519)
[![crates.io](https://meritbadge.herokuapp.com/ecies-ed25519)](https://crates.io/crates/ecies-ed25519)
![checks](https://github.com/phayes/ecies-ed25519/workflows/checks/badge.svg)
[![codecov](https://codecov.io/gh/phayes/ecies-ed25519/branch/master/graph/badge.svg)](https://codecov.io/gh/phayes/ecies-ed25519)


ECIES on Twisted Edwards Curve25519 using AES-GCM. 

ECIES can be used to encrypt data using a public key such that it can only be decrypted by the holder of the corresponding private key. 

It uses the excellent [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek) library for ECC operations, 
and provides two different backends for HKDF/AEAD/AES-GCM operations. 

1. The `ring` backend (default) uses [ring](https://github.com/briansmith/ring).  It uses rock solid primitives based on 
BoringSSL, but cannot run on all platforms. For example it won't work on WASM.

2. The `pure_rust` backend. It uses a collection of pure-rust implementations of SHA2, HKDF, AES, and AEAD, which will work
on all platforms. However, some of these implementations haven't been thoroughly reviewed. To activate this backend add this to your Cargo.toml file: ` ecies-ed25519 = { version = "0.1", features=["pure_rust"] }`.


### Example Usage
```rust
let mut csprng = rand::thread_rng();
let (secret, public) = ecies_ed25519::generate_keypair(&mut csprng);

let message = "I 💖🔒";

// Encrypt the message with the public key such that only the holder of the secret key can decrypt.
let encrypted = ecies_ed25519::encrypt(&public, message.as_bytes(), &mut csprng).unwrap();

// Decrypt the message with the secret key
let decrypted = ecies_ed25519::decrypt(&secret, &encrypted);
```

### Running Tests

You should run tests on both backends:
```
cargo test --no-default-features --features ring
cargo test --no-default-features --features pure_rust
```
