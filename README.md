# tmpk - TPM2 key and storage management toolkit

[![GoDoc](https://godoc.org/github.com/folbricht/tpmk?status.svg)](https://godoc.org/github.com/folbricht/tpmk)

This toolkit strives to simplify common tasks around key and certificates involving TPM2. It also provides the tools necessary to make use of keys in the module for TLS connections and OpenPGP in Go. It does not attempt to provide a feature-rich interface to support all possible use-cases and features. tpmk consists of a Go library and a tool with a simple interface. It currently provides:

- Generating RSA/SHA256 primary keys in the TPM and exporting the public key
- Generating x509 certificates and signing with a (file) CA
- Writing of arbitrary data to NV storage - intended to be used to store certificates
- Creating SSH certificates for keys in the TPM
- Generating OpenPGP public keys based on RSA keys in the TPM
- OpenPGP Signing and Decryption

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
  - `ls` List persistent keys

- `nv` Contains commands to operate on non-volatile indexes in the TPM

  - `write` Write arbitrary data into an index
  - `read` Read data from an index
  - `rm` Delete data in an index
  - `ls` List indexes

- `x509` Offers commands to generate and sign certificates

  - `generate` Generate a new certificate for a public key and sign it

- `ssh` Commands to operate on SSH certificates

  - `certificate` Create and sign an SSH certificate
  - `pub` Convert a PKCS1 key to OpenSSH format
  - `client` Start SSH client and execute remote command

- `openpgp` Commands to use keys in OpenPGP format

  - `generate` Create an OpenPGP identity based on a key in the TPM
  - `sign` Sign data with a TPM key
  - `decrypt` Decrypt data using the private TPM key

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

### SSH certificate generation

This example shows how to create an SSH certificate for a key in the TPM. It also covers reading and converting a key to OpenSSH format. The key is assumed to be present in the TPM already. An earlier example shows how to generate one.

First, the public key is read from the TPM. The result is PEM encoded PKCS#1.

```sh
tpmk key read 0x81000000 pub.pem
```

To generate and sign an SSH certificate, an SSH CA key is required which is provided as file (ssh-ca) in this example. A key identifier, serial or certificate option can be provided. If the generated certificate is to be stored in an NV index, the `-f wire` option is recommended as this will produce a more compact encoding.

```sh
tpmk ssh certificate --ca-key ssh-ca --id myKey -O force-command=ls pub.pem tpm-cert.pub
```

If a public key conversion to OpenSSH format is needed, the `pub` subcommand can be used.

```sh
tpmk ssh pub pub.pem id_rsa.pub
```

As before, these commands can be chained together via STDOUT/STDIN by providing `-` in place of filenames.

### Open SSH connection using public key authentication with TPM key

The following example shows how to utilize a TPM key to open an SSH connection to a server using [golang.org/x/crypto/ssh](https://godoc.org/golang.org/x/crypto/ssh) as client.

First open the TPM device or simulator. The key 0x81000000 is assumed to be present and will be used for authentication.

```go
const (
  keyHandle = 0x81000000
  password  = ""
)

dev, err := tpmk.OpenDevice("/dev/tpmrm0")
if err!=nil{
    panic(err)
}
defer dev.Close()
```

Read the public key from the TPM and use it to create crypto.Signer which can be used to build an ssh.Signer used in public key authentication.

``` go
// Use the private key in the TPM
private, err := tpmk.NewRSAPrivateKey(dev, keyHandle, password)
if err != nil {
  panic(err)
}
// Create an ssh.Signer to be used for key authentication
signer, err := ssh.NewSignerFromSigner(private)
if err != nil {
  panic(err)
}
// Build the client configuration
config := &ssh.ClientConfig{
  User: "username",
  Auth: []ssh.AuthMethod{
    ssh.PublicKeys(signer),
  },
  HostKeyCallback: ssh.InsecureIgnoreHostKey(),
}
```

Open the SSH client connection. The public key in OpenSSH format needs to be setup on the server for authentication to succeed.

```go
client, err := ssh.Dial("tcp", "hostname:22", config)
if err != nil {
  panic(err)
}

session, err := client.NewSession()
if err != nil {
  panic(err)
}
defer session.Close()

b, err := session.Output("/usr/bin/whoami")
if err != nil {
  panic(err)
}
fmt.Println(string(b))
```

### Create an OpenPGP identity and sign data with it

This example shows how to produce an OpenPGP public key (identity) and use it to sign data.

In order to sign with a TPM key, an OpenPGP identity needs to be created with name and email address. This identity contains the public key and should be stored (either separately or in a TPM NV index). For this command, the key (handle 0x81000000 in this example) has to be present in the TPM already and must have the `sign` attribute to allow signing.

```sh
tpmk openpgp generate -n Testing -e test@example.com 0x81000000 identity.pgp
```

The same key and identity should be used when signing data. In this case a detached and armored signature is created and written to STDOUT.

```sh
tpmk openpgp sign -a 0x81000000 identity.pgp data.txt -
```

## Links

- TPM2 specification - [https://trustedcomputinggroup.org/resource/tpm-library-specification/](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- Go TPM2 library used by tpmk - [https://github.com/google/go-tpm](https://github.com/google/go-tpm)
- IBM TPM2.0 Simulator - [https://sourceforge.net/projects/ibmswtpm2/](https://sourceforge.net/projects/ibmswtpm2/)
