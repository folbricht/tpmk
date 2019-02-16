# tmpk - TPM2 key and storage management toolkit

This toolkit strives to simplify common tasks around key and certificates involving TPM2. It also provides the tools necessary to make use of keys in the module for TLS connections in Go. It does not attempt to provide a feature-rich interface to support all possible use-cases and features. tpmk consists of a Go library and a tool with a simple interface. It currently provides:

- Generating RSA/SHA256 keys in the TPM and exporting the public key
- Generating x509 certificates and signing with a (file) CA
- Writing of arbirary data to NV storage - intended to be used to store certificates

A range of features and options are **not** available at this point, but may be implemented in the future. Suggestions and contributions are welcome.

- Generating ECC keys
- PCRs
- TPM policies
- Only supports the owner hierarchy

## Libary

TODO

## Tool

The tool is provided for convenience and should allow the use of the most common features. Some of the operations offered by its sub-commands, like `x509` can be performed with more feature-rich tools such as `openssl`.

### Installation

```text
go get -u github.com/folbricht/tpmk/cmd/tpmk
```

### Sub-Commands

- `key` Groups commands that operate on keys in the TPM

  - `generate` Generates a new primary key and makes it persistent
  - `rm` Removes a persistent key

- `nv` Contains commands to operate on non-volatile indexes in the TMP

  - `write` Write arbitrary data into an index

- `x509` Offers commands to generate and sign certificates

  - `generate` Generate a new certificate for a public key and sign it

### Use-cases / Examples

#### RSA key generation and certificate storage in NV

In this example, the goal is to have an RSA key generated in the TPM, and have a signed certificate for the key stored in NV in the TPM. This allows a machine to retain a signed key+certificate without relying on disk storage. While the generated keys doesn't leave the module, the CA to sign it is expected to be available as files at time of signing.

Generate the key in the TPM and write the public key (in PEM format) to disk.

```sh
tpmk key generate 0x81000000 pub.pem
```

Build a certificate using the public key and signing it with a (file) CA and writing it to disk in PEM format. Options to set the common name, SAN properties, expiry, and others are available.

```sh
tpmk x509 generate -c ca.crt -k ca.key -f der pub.pem cert.pem
```

Store the (signed) certificate in the TPM in an NV storage index. This command stores the PEM cert which is not recommended since the amount of data that can be stored in a single NV index is limited. A large PEM may not fit. It'd be better to store the cert in DER format instead (available with `--out-format=der` option above).

```sh
tpmk nv -d sim write 0x1500000 cert.pem
```

The following does the same, but passes the data through STDIN/STDOUT without storing anything on disk. It also stores the certificate in DER format instead of PEM to ensure it fits into the NV index.

```sh
tpmk key generate 0x81000000 - | tpmk x509 generate -c ca.crt -k ca.key --out-format=der - -| tpmk nv write 0x1500000 -
```
