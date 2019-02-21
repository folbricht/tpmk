# tmpk - TPM2 key and storage management toolkit

This toolkit strives to simplify common tasks around key and certificates involving TPM2. It also provides the tools necessary to make use of keys in the module for TLS connections in Go. It does not attempt to provide a feature-rich interface to support all possible use-cases and features. tpmk consists of a Go library and a tool with a simple interface. It currently provides:

- Generating RSA/SHA256 keys in the TPM and exporting the public key
- Generating x509 certificates and signing with a (file) CA
- Writing of arbirary data to NV storage - intended to be used to store certificates
- Creating SSH certificates for keys in the TPM

A range of features and options are **not** available at this point, but may be implemented in the future. Suggestions and contributions are welcome.

- Generating ECC keys
- PCRs
- TPM policies
- Only supports the owner hierarchy

## Tool

The tool is provided for convenience and should allow the use of the most common features. Some of the operations offered by its sub-commands, like `x509` can be performed with more feature-rich tools such as `openssl`. The tool is able to operate on a TPM 2.0 simulator (use option `-d sim`).

### Installation

```text
go get -u github.com/folbricht/tpmk/cmd/tpmk
```

### Sub-Commands

- `key` Groups commands that operate on keys in the TPM

  - `generate` Generates a new primary key and makes it persistent
  - `read` Reads the public key
  - `rm` Removes a persistent key

- `nv` Contains commands to operate on non-volatile indexes in the TMP

  - `write` Write arbitrary data into an index
  - `read` Read data from an index
  - `rm` Delete data in an index
  - `ls` List indexes

- `x509` Offers commands to generate and sign certificates

  - `generate` Generate a new certificate for a public key and sign it

- `ssh` Commands to operate on SSH certificates

  - `certificate` Create and sign an SSH certificate

## Use-cases / Examples

### RSA key generation and certificate storage in NV

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

### Establishing a mutual TLS connection using a TPM key

Here the goal is to use a key from the TPM to establish a mutual TLS connection with a server. The key is assumed to have been generated already (see prior example). While not strictly neccessary, the signed x509 is kept in NV as well.

Start off with some setup. Defining the handle/index that hold the key and certificate and open the TPM.

```go
const (
  keyHandle = 0x81000000
  nvHandle  = 0x1500000
  password  = ""
)

// Open the TPM
dev, err := tpmk.OpenDevice("/dev/tpmrm0")
if err!=nil{
    panic(err)
}
defer dev.Close()
```

The next step is to create a crypto.PrivateKey that can be used in the TLS negotiation, as well as loading the x509 certificate from NV.

```go
// Use the private key in the TPM
private, err := tpmk.NewRSAPrivateKey(dev, keyHandle, password)
if err != nil {
  panic(err)
}

// Read the certificate (DER format) from NV
certDER, err := tpmk.NVRead(dev, nvHandle, password)
if err != nil {
  panic(err)
}
```

With the client certificate and key it's now possible to build the TLS client config. The CA certificate is also required to trust the server.

```go
// Build the client certificate for the mutual TLS connection
clientCrt := tls.Certificate{
  Certificate: [][]byte{certDER},
  PrivateKey:  private,
}

// Load the CA certificate
caCrt, err := tpmk.LoadX509CertificateFile("ca.crt")
if err != nil {
  panic(err)
}

// Build the client TLS config
root := x509.NewCertPool()
root.AddCert(caCrt)
clientCfg := &tls.Config{
  Certificates: []tls.Certificate{clientCrt},
  RootCAs:      root,
}
```

Using the TLS client config, the client can now connect to a server that expects a client certificate. The client key remains in the TPM.

```go
// Connect to the server
conn, err := tls.Dial("tcp", "localhost:1234", clientCfg)
if err != nil {
  panic(err)
}
defer conn.Close()
conn.Write([]byte("hello"))
```

## Links

- TPM2 specification - [https://trustedcomputinggroup.org/resource/tpm-library-specification/](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- Go TPM2 library used by tpmk - [https://github.com/google/go-tpm](https://github.com/google/go-tpm)
- GoDoc for the tpmk library - [https://godoc.org/github.com/folbricht/tpmk](https://godoc.org/github.com/folbricht/tpmk)
- IBM TPM2.0 Simulator - [https://sourceforge.net/projects/ibmswtpm2/](https://sourceforge.net/projects/ibmswtpm2/)
