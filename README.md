# SolRsaVerify

[![test](https://github.com/adria0/SolRsaVerify/actions/workflows/test.yml/badge.svg)](https://github.com/adria0/SolRsaVerify/actions/workflows/test.yml) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Verification of RSA Sha256 Pkcs1.5 Signatures

This kind of signatures (with PSS) are standard in CryptoAPIs when generating RSA signatures.

Checked results with FIPS test vectors https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-2rsatestvectors.zip file SigVer15_186-3.rsp

# Usage with OpenSSL (OpenSSL 3.1.1)

First you'll need an RSA private key. You can generate one using the
`openssl` cli:


    $ openssl genrsa -out private.pem 1024
    Generating RSA private key, 1024 bit long modulus
    ................................................++++++
    ..................................................++++++
    e is 65537 (0x10001)


Next lets sign a message:


    $ echo -n "hello world" | openssl dgst -sha256 -sign private.pem | xxd -p | tr -d \\n
    00d5380ea463dcb195e887bd900c2e25098401378d6da2e97e56ef1b984e6a67959f7adc662727e0c1e3ea3580caecba6a69925eec3704413e2192b0ff40f4711d424e4e1ecc6128534a2527c04bb1576c4582a589559a8ff9ad2bfd5f09f856dfefd90cd0464dee63f7b10d0b5ef69c389bc4ef4a9d35254fcad5ad246cc6a3%


We pass the string "hello world" to openssl to sign it and then to `xxd` to
convert from binary to hex and finally to `tr` to truncate newlines.

Now let's extract the public key from the private key:


    $ openssl rsa -in private.pem -outform der -pubout -out public.pem
    writing RSA key


And finally we need to extract `n` (the modulus) from the public key:


    $  openssl asn1parse -inform PEM -i -in public.pem -strparse 18
    0:d=0  hl=3 l= 137 cons: SEQUENCE
    3:d=1  hl=3 l= 129 prim:  INTEGER           :B793F2F926170FAD768F8B1A5769A2243B4CDCAC4780194F59B39E1A2ABC3BB8EA42DB495D17BEC7F7072A11ED4FA510E75A7886A5DB6F71B7AFCA0090CA079889D18AF0669829ED29A8E21D0C09BD19CAAF2FE2CC8121BFC5687AC6698E3022F468A481426486CAD263BE1A119491E034A6E1AB78F19C066D4145A50F9ECFF7
    135:d=1  hl=2 l=   3 prim:  INTEGER           :010001


Now we can call `RsaVerify.pkcs1Sha256Raw` and verify the signature:

```
modulus = "0xB793F2F926170FAD768F8B1A5769A2243B4CDCAC4780194F59B39E1A2ABC3BB8EA42DB495D17BEC7F7072A11ED4FA510E75A7886A5DB6F71B7AFCA0090CA079889D18AF0669829ED29A8E21D0C09BD19CAAF2FE2CC8121BFC5687AC6698E3022F468A481426486CAD263BE1A119491E034A6E1AB78F19C066D4145A50F9ECFF7";

exponent= "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";

signature = "0x57a0d6a185924d9d579b3ab319fe512331cb0bc6ef2da7d5285cbd06844f5c44662cae2e41ee5020893d6690e34b50a369a78250ae81ba6d708560535ef7cff0299f2ba070b096a9a76e84cf9c902b5e367b341ee166f5fc325dd08a3d971d96d528937f617a1eaf2250c56c4edca80c65970d54fe2492a19468bd32166b3c32";

ok = contract.pkcs1Sha256Raw(message, signature, exponent, modulus);
````
