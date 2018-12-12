# SolRsaVerify: Verification of RSA Sha256 Pkcs1.5 Signatues
This kind of signatures (with PSS) are standard in CryptoAPIs when generating RSA signatures.

Checked results with FIPS test vectors https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-2rsatestvectors.zip file SigVer15_186-3.rsp

Forked from [adriamb/SolRsaVerify](https://github.com/adriamb/SolRsaVerify), dramatically reduces the gas cost of signature verification for cases where public key `e` fits in a `uint` type. This is useful, because, in practice, e=65537 is almost always used.
