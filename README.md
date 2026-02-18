# mcuboot-rs

A library to read and parse MCUboot images written in rust 🦀

With this library you can easily access the image's hashes and signature.

## Usage

```rust
let path = std::path::Path::new("test/test_image.signed.bin");
let image_metadata = mcuboot_rs::parse_image(&path).expect("Failed to parse image");

println!("Image header:\n{:#?}", image_metadata.header);
println!("Image sha256_hash: {:#?}", image_metadata.sha256_hash);
println!("Image signature: {:#?}", image_metadata.signature);
println!("Image signature_key_hash: {:#?}", image_metadata.signature_key_hash);
```

## Known limitations

### Protected TLV

Currently the protected TLV area is not extracted from the image.
It would be a simple addition to be added, but I never had a MCUBoot image with the protected area present to be able to verify the code.
If you require this feature, feel free to open an issue or PR :)

## License

mcuboot-rs is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
