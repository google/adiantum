# HPolyC

For many storage encryption applications, the ciphertext must be the same size as the plaintext;
generally this matches the disk sector size of either 512 or 4096 bytes. This means that standard
approaches like AES-GCM or RFC7539 cannot be applied. The standard solution is AES-XTS, but
this has two disadvantages:

- If AES hardware is absent, AES is relatively slow, especially constant-time implementations
- Using XTS, a one-bit change to the plaintext means only a 16-byte change to the ciphertext,
  revealing more to the attacker than necessary.

HPolyC uses a fast polynomial hash (Poly1305) and a fast stream cipher (XChaCha12) to build
a construction which encrypts an entire sector at a time. On
an ARM Cortex-A7 processor, HPolyC decrypts 4096-byte messages at 14.5 cycles
per byte, over four times faster than AES-256-XTS. HPolyC is also a "super
pseudorandom permutation" over the whole sector, which means that any change to the plaintext
of the sector results in an unrecognizably different ciphertext sector and vice versa.

HPolyC is published as [ePrint report 2018/720](https://eprint.iacr.org/2018/720).

This repository includes:

- LaTeX sources for the paper presenting HPolyC
- A reference implementation of HPolyC in Python
- Test vectors in JSON for HPolyC
- Test vectors in JSON for Poly1305, Salsa20, XSalsa20, ChaCha, XChaCha

This is not an officially supported Google product.
