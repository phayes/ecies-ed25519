# ecies-ed25519
[![docs](https://docs.rs/ecies-ed25519/badge.svg)](https://docs.rs/ecies-ed25519)
[![crates.io](https://meritbadge.herokuapp.com/ecies-ed25519)](https://crates.io/crates/ecies-ed25519)
![checks](https://github.com/phayes/ecies-ed25519/workflows/checks/badge.svg)
[![codecov](https://codecov.io/gh/phayes/ecies-ed25519/branch/master/graph/badge.svg)](https://codecov.io/gh/phayes/ecies-ed25519)


ECIES on Twisted Edwards Curve25519 using AES-GCM and HKDF-SHA256.

ECIES can be used to encrypt data using a public key such that it can only be decrypted by the holder of the corresponding private key. 

*This project has not undergone a security audit. A 1.0 release will not happen until it does.*


### Backends

It uses the excellent [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) library for ECC operations, and provides two different backends for HKDF-SHA256 / AES-GCM operation operations. 
    
1. The `pure_rust` backend (default). 
   It uses a collection of  pure-rust implementations of SHA2, HKDF, AES, and AEAD.

2. The `ring` backend uses [ring](https://github.com/briansmith/ring).  It uses rock solid primitives based on BoringSSL, but cannot run on all platforms. For example it won't work on WASM. To activate this backend add this to your Cargo.toml file: 

   ` ecies-ed25519 = { version = "0.3", features = ["ring"] }`

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

### `serde` Support

The `serde` feature is provided for serializing / deserializing private and public keys.


### Running Tests

You should run tests on both backends:
```
cargo test --no-default-features --features "ring serde"
cargo test --no-default-features --features "pure_rust serde"
```

### Performance

If using the `pure_rust` backend, by default this crate's dependencies will use software implementations of both AES and the POLYVAL universal hash function.

When targeting modern x86/x86_64 CPUs, use the following RUSTFLAGS to take advantage of high performance AES-NI and CLMUL CPU intrinsics:
```
RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"
```

### Future Plans

 - I will be making this crate generic over both the AEAD and HKDF implementation once [const-generics](https://github.com/rust-lang/rust/issues/44580) is resolved.
 
 - Add support for [AVX2 and AVX512](https://github.com/dalek-cryptography/curve25519-dalek#backends-and-features)
