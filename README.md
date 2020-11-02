# libMCTP

libMCTP is a MCTP (Management Component Transport Protocol) implementation
for Rust.

libMCTP aims to implement the MCTP protocol as described in the [DMTF DSP2016
specification](https://www.dmtf.org/sites/default/files/standards/documents/DSP2016.pdf).

MCTP allows multiple transport layers, the protocols currently supported by
this library include:
 * SMBus/I2C version 1.2.0. See [DMTF DSP0237](https://www.dmtf.org/sites/default/files/standards/documents/DSP0237_1.2.0.pdf)

All naming conventions are based on the names used in the specifications.

## Using libMCTP

libMCTP can be used in any Rust project. libMCTP does not depend on the Rust
std library meaning that it can also be used in embedded applications.

For details and examples on using libMCTP see the auto generated Rust docs.

## License

See the `LICENSE` file for details.

## Code contributions

Code contributions are very encouraged!

To contribute code you can open a GitHub pull request. To allow for easier
review please split commits up into smaller chunks and ensure that each commit
passes all of these cargo commands:

```shell
cargo fmt; cargo build; cargo test; cargo clippy
```

If in doubt just open a PR and we can discuss from there.
