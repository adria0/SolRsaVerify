# SolRsaVerify

[![Build Status](https://travis-ci.org/adriamb/SolRsaVerify.svg?branch=master)](https://travis-ci.org/adriamb/SolRsaVerify)

Verification of RSA Sha256 Pkcs1.5 Signatues

This kind of signatures (with PSS) are standard in CryptoAPIs when generating RSA signatures.

Checked results with FIPS test vectors https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-2rsatestvectors.zip file SigVer15_186-3.rsp

# Usage

First you'll need an RSA private key. You can generate one using the
`openssl` cli:


    $ openssl genrsa -out private.pem 1024
    Generating RSA private key, 1024 bit long modulus
    ................................................++++++
    ..................................................++++++
    e is 65537 (0x10001)


Now let's extract the public key:


  $ openssl rsa -in private.pem -outform der -pubout -out public.pem
  writing RSA key

Keys can be in either `PEM` or `DER` format. `SolRsaVerify` uses DER format.

Next lets sign a message:

    $ echo "hello world" | openssl dgst -sha256 -sign private.pem -out | xxd -p | tr -d \\n
    00d5380ea463dcb195e887bd900c2e25098401378d6da2e97e56ef1b984e6a67959f7adc662727e0c1e3ea3580caecba6a69925eec3704413e2192b0ff40f4711d424e4e1ecc6128534a2527c04bb1576c4582a589559a8ff9ad2bfd5f09f856dfefd90cd0464dee63f7b10d0b5ef69c389bc4ef4a9d35254fcad5ad246cc6a3%

We pass the string "hello world" to openssl to sign it and then to `xxd` to
convert from binary to hex and finally to `tr` to truncate newlines.

Now let's print out the public key in hex format:

  $ xxd -p public.pem |  tr -d \\n
  30819f300d06092a864886f70d010101050003818d0030818902818100b249b903c5f3e1451e8cae3948af83f2cf759c4c6ec9ada87318f9bb4cb96e2db2c9450dffc8efc0179a2fd38b1f6b99839e41df8e56746b47fffa002915ef8fe2bd96723a0e75dadfe10666ebdad348dd773c30f2cc86770190e8563eed7ea5348da7a01eb179b7d154e06e9c60e1c18da31c2d19789a8be7593cfec5703ff30203010001%

An finally need the modulus and exponent:

    $ openssl rsa -in private.pem -text -noout

Now we can call `SolRsaVerify.pkcs1Sha256VerifyRaw` and verify the signature:

   const modulus= "0xb249b903c5f3e1451e8cae3948af83f2cf759c4c6ec9ada87318f9bb4cb96e2db2c9450dffc8efc0179a2fd38b1f6b99839e41df8e56746b47fffa002915ef8fe2bd96723a0e75dadfe10666ebdad348dd773c30f2cc86770190e8563eed7ea5348da7a01eb179b7d154e06e9c60e1c18da31c2d19789a8be7593cfec5703ff3"
   const exponent= "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001"
   const signature = "0x00d5380ea463dcb195e887bd900c2e25098401378d6da2e97e56ef1b984e6a67959f7adc662727e0c1e3ea3580caecba6a69925eec3704413e2192b0ff40f4711d424e4e1ecc6128534a2527c04bb1576c4582a589559a8ff9ad2bfd5f09f856dfefd90cd0464dee63f7b10d0b5ef69c389bc4ef4a9d35254fcad5ad246cc6a3";
   const publicKey = "0x30819f300d06092a864886f70d010101050003818d0030818902818100b249b903c5f3e1451e8cae3948af83f2cf759c4c6ec9ada87318f9bb4cb96e2db2c9450dffc8efc0179a2fd38b1f6b99839e41df8e56746b47fffa002915ef8fe2bd96723a0e75dadfe10666ebdad348dd773c30f2cc86770190e8563eed7ea5348da7a01eb179b7d154e06e9c60e1c18da31c2d19789a8be7593cfec5703ff30203010001";

  contract = await SolRsaVerify.new();
  const result = contract.pkcs1Sha256VerifyRaw(message, signature, exponent, modulus);
  console.log(`The result was: ${result}`)
  # => The result was: 0

(Note: don't forget to prefix the hex values with 0x)
