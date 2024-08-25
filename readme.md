# README for TinyES3
TinyES3 is an Embedded Secure Signing Server that uses an encryped key storage, EKS.
The server uses the private elliptic curves keys stored in the EKS to generate the
digital signatures. The signature is based on selectable signing keys which are
securely stored on the server. The signing keys can be generated on the server itself.
Thanks to the EKS, it is easy to clone the server and create a redundant, highly
available signing system.

The server can be used to sign embedded files like firmware uploads. A corresponding
signature header will be added in front of the original file. To verify the file on
the recipient side, the coresponding public key must be available on the recipient.

The signature process requires not only the server, but also a command line
application, the client. The file to be signed is first hashed by the client and
this hash is then sent to the server. The hash signature is now created on the server
and sent back to the client. Here the signature header is created and placed in front
of the original file.

More information are available here: 
https://www.emb4fun.de/projects/tes3/index.html

# Some notes about Mbed TLS
Mbed TLS is used in .\source\common\library\mbedtls and was copied from the following project:
https://github.com/ARMmbed/mbedtls