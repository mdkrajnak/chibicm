# Chibi Certificate Management

Chibi Certificate Management is a light-weight certificate management solution
for use during software development. It is not intended for production use.

"Chibi" is "small" in Japanese and meant as a reminder of its limited scope.

## Overview

Chibi CM's goals include:

* Generate simple multi-certificate systems
* Generate self-signed certificates.
* Work on Linux and Windows.
* Be simple, but make the certificate generation workflow explicit.

To make the worflow explicit, Chibi CM is built with two distinct roles in mind:

* A Cerificate Authority (CA), responsible for issuing certificates.
* A CA user that requests a certificate from the CA.

And includes two distinct programs, one for each role:

* `ccauth` that implments the commands for a CA.
* `ccuser` that implments the commands for a CA user.

While it is possible that the same person or team may wind up performing both roles,
supporting them as separate programs helps with managing the certificate process.

As a result Chibi CM is more complicated than aggressively simplified
tools like [easyca](https://github.com/zufallsgenerator/easyca),  [minica](https://github.com/jsha/minica), or [mkcert](https://github.com/FiloSottile/mkcert),
but substantially less complicated than the [smallstep](https://smallstep.com/)
CA server or [tinyca](https://opsec.eu/src/tinyca/). Please check them
out as possible alternatives to Chibi CM.

## Quick Start

The simpliest way to start and issue a single certificate with Chibi CM is:

* CA creates a new root certificate (one time operation).
* CA user creates a request for a new certificate and submits it to the CA.
* CA verifies the request and signs it to create a new certificate.

Using the following commands:

```bash
ccauth new
ccuser csr --name myclient
ccauth sign --name myclient
```

Additional certificates after the first only require the last two commands.
```bash
ccuser csr --name anotherclient
ccauth sign --name anotherclient
```

The `ccuser` command can alse be used to create self-signed certificates:

```bash
ccuser self --name myself
```

## Detailed Usage

There are four use cases Chibi CM is meant to support.

* Create new root CAs.
* Create certificate signing requests for end-entities or intermediates.
* Sign client certificate signing requests.
* Create self-signed certificates.

## Create a New Root CA

The `ccauth new` command can be used to create a new root CA. A root CA may have a name
which is given with the `--name` option, but defaults to `root` if not specifiied. The
specfied same is also used as the certificates common name.

The full set of options includes:

* `--name` The CA's common name. Default: root.
* The CA's distingushed name.
  * `--organization`
  * `--unit`
  * `--country`
  * `--state`
  * `--location`
  * `--email`
* `--bits`, the size of the key. Default: 2048.
* `--start`, the state date/time. Default: current time.
* `--days`, the number of days the root certificate is valid. Default: 365.
* `--help`, prints help on the new command.

The command generates a self-signed root certificates and private keys. By default, 
these are saved in the files:

* root.crt. The root CA certificate and public key.
* root.key. The private key.

All files are stored in PEM format.

You may create additional root CAs if you give the certificate a unique 
name.

## Create Certificate Signing Requests

The `ccuser csr` command can be used by a CA user to create a 
CSR (certificate signing request) to send to the CA for signing.

The full set of options includes.

* `--name` The requested client certificate's common name. Required.
* The requested client certificate's distingushed name.
  * `--organization`
  * `--unit`
  * `--country`
  * `--state`
  * `--location`
  * `--email`
* `--bits`, the size of the key. Default: 2048.
* `--san`, zero or more SANs to associate with the certificate.
* `--isca`, request is for an intermediate certificate to sign other certificates.
* `--help`, prints help on the csr command.

It has most of the same options as creating the root certificate except
for the start date and duration. Start and duration are specified at the
time the CSR is signed.

The CSR has two additional options. One, `--isca`, means the signed
certificate is intended to be used to sign other certificates. The
other `--san` is used to associate one or more Subject Alternate Names
with the certificate. For example:

```bash
ccuser csr --name myserver --organization Me --unit Myself --san localhost 127.0.0.1
```

Creates a CSR for the "Me" organization with two SANs: "localhost" and "127.0.0.1".
The CSR is saved in the file myserver.csr.

Note that SANs should be IP addresses or DNS names assoctiated with the scope
of the certificate, or an email address associated with the owner. Normally
the --san option and --isca are not used together.

For server certificates the common name is typcially the full DNS name of the
domain being served, and the best practice is to include that domain in the
SAN list. Chibi CM is meant to support other use cases than web servers so it
does not require the common name to be a domain or automatically include it in 
the SAN list.

If you are creating a server certificate we recommend that you make sure that 
the SAN list includes every name explicitly.

The command creates two files:

* \<name\>.csr. The CSR for the certificate specified with `--name`.
* \<name\>.key. The private key.

In theory the generated CSR could be sent to any CA.

## Sign Client Certificate Signing Requests

The `ccauth sign` command can be used by a CA to sign a CSR.

The full set of options includes:

* `--name`, The common name associated with the signing request. Required.
* `--ca`, The name of the CA used to sign the CSR. Default: "root".
* `--start`, the state date/time. Default: the current time.
* `--days`, the number of days the root certificate is valid. Default: 365.
* `--help`, prints help on the sign command.

The commands reads in the corresponding CSR file based on the `--name`
argument. The CA private key must be in the same directory.

The generated certficate will have the same name as the CSR. So if
`ccauth` is used to sign `myserver.csr`, the generated certificate
will be in the file `myserver.crt`. The certificate file holds the 
completed certificate chain for `myserver`, with the new certificate first.

In order to complete the certificate chain the certificate of the CA used to
sign the certificates, and any parents it has, must be in the same directory.

## Create Self-Signed Certificates

The `ccuser self` command can be used by a non-CA user to generate a 
self-signed certificate.

The full set of options includes:

* `--name`, the requested client certificate's common name. Required.
* The subject's distingushed name.
  * `--organization`
  * `--unit`
  * `--country`
  * `--state`
  * `--location`
  * `--email`
* `--bits`, the size of the key. Default: 2048.
* `--san`, zero or more SANs.
* `--start`, the state date/time. Default: current date.
* `--days`, the number of days the root certificate is valid. Default: 365.
* `--help`, prints help on the self command.

The `self` command creates a self-signed certificate and private key and stores
them in the files:

* \<name\>.crt. The certificate with the name given by `--name`.
* \<name\>.key. The private key.

## File Management

`ccauth` and `ccuser` operate out of the users current working directory. 

`ccauth` and `ccuser` generally use the `--name` parameter to determine the
names of input and output files except when signing applications `--ca` is
used to find the file with the CA's private key.

In order to keep your system secure at a *minimum* make sure that private
key files are only accessible to the owning user. Practically this means
having a working directory for your Chibi CM files that is only accessible
to the one user who mananges the keys. 

Certificates that are created can be copied to suitable trust and key stores.

Because Chibi CM seperates the CA and CA user roles, there may be different
directories for these files.

Using a root CA to create intermediate CA's can further complicate this 
process. When a certificate is signed, `ccauth sign` attempts to write out
the full certificate chain. This will only succeed if all the relevant
certificates are in the current working directory.






