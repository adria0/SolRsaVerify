// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

/*
    Copyright 2016, Adrià Massanet

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    
    Checked results with FIPS test vectors
    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-2rsatestvectors.zip
    file SigVer15_186-3.rsp
    
 */

library RsaVerifyOptimized {
    uint256 constant sha256ExplicitNullParamByteLen = 17;
    bytes32 constant sha256ExplicitNullParam =
        0x3031300d06096086480165030402010500000000000000000000000000000000;
    bytes32 constant sha256ExplicitNullParamMask =
        0xffffffffffffffffffffffffffffffffff000000000000000000000000000000;

    uint256 constant sha256ImplicitNullParamByteLen = 15;
    bytes32 constant sha256ImplicitNullParam =
        0x302f300b06096086480165030402010000000000000000000000000000000000;
    bytes32 constant sha256ImplicitNullParamMask =
        0xffffffffffffffffffffffffffffff0000000000000000000000000000000000;

    /** @dev Verifies a PKCSv1.5 SHA256 signature
     * @param _sha256 is the sha256 of the data
     * @param _s is the signature
     * @param _e is the exponent
     * @param _m is the modulus
     * @return true if success, false otherwise
     */
    function pkcs1Sha256(
        bytes32 _sha256,
        bytes memory _s,
        bytes memory _e,
        bytes memory _m
    ) public view returns (bool) {
        // decipher
        uint256 decipherlen = _m.length;
        if (decipherlen < 64) {
            return false;
        }
        if (decipherlen != _s.length) {
            return false;
        }
        bytes memory input = bytes.concat(
            bytes32(decipherlen),
            bytes32(_e.length),
            bytes32(decipherlen),
            _s,
            _e,
            _m
        );
        uint256 inputlen = input.length;

        bytes memory decipher = new bytes(decipherlen);
        assembly ("memory-safe") {
            if iszero(staticcall(not(0), 0x05, add(input, 0x20), inputlen, add(decipher, 0x20), decipherlen)) {
                mstore(0x00, false)
                return(0x00, 0x20)
            }
        }

        // Check that is well encoded:
        //
        // 0x00 || 0x01 || PS || 0x00 || DigestInfo
        // PS is padding filled with 0xff
        // DigestInfo ::= SEQUENCE {
        //    digestAlgorithm AlgorithmIdentifier,
        //      [optional algorithm parameters]
        //    digest OCTET STRING
        // }

        uint digestAlgoWithParamLen;
        uint256 paddingLen;
        assembly ("memory-safe") {
            //
            // Equivalent code:
            // if (uint8(decipher[decipherlen - 50]) == 0x31) {
            //     hasNullParam = true;
            //     digestAlgoWithParamLen = sha256ExplicitNullParamByteLen;
            // } else if (uint8(decipher[decipherlen - 48]) == 0x2f) {
            //     hasNullParam = false;
            //     digestAlgoWithParamLen = sha256ImplicitNullParamByteLen;
            // } else {
            //     return false;
            // }

            // Note: `decipherlen` is at least 64, so we can safely access
            if eq(
                byte(
                    0,
                    mload(
                        sub(add(decipher, decipherlen),18 /* decipher+0x20+(decipherlen-50) */)
                    )
                ),
                0x31
            ) {
                digestAlgoWithParamLen := sha256ExplicitNullParamByteLen
            }
            if iszero(digestAlgoWithParamLen) {
                if eq(
                    byte(
                        0,
                        mload(
                            sub(add(decipher, decipherlen), 16 /* decipher+0x20+(decipherlen-48) */)
                        )
                    ),
                    0x2f
                ) {
                    digestAlgoWithParamLen := sha256ImplicitNullParamByteLen
                }
            }
            if iszero(digestAlgoWithParamLen) {
                mstore(0x00, false)
                return(0x00, 0x20)
            }


            // paddingLen = decipherlen - 5 - digestAlgoWithParamLen - 32;
            // Note: `decipherlen` is at least 64, so we can safely access
            paddingLen := sub(sub(decipherlen, digestAlgoWithParamLen), 37)

            //
            // Equivalent code:
            //
            // if (decipher[0] != 0 || decipher[1] != 0x01) {
            //     return false;
            // }
            //
            if sub(
                and(
                    mload(add(decipher, 0x20)),
                    0xffff000000000000000000000000000000000000000000000000000000000000 /* 32bytes */
                ),
                0x0001000000000000000000000000000000000000000000000000000000000000 /* 32bytes */
                /*
                    0: 0x00
                    1: 0x01
                */
            ) {
                mstore(0x00, false)
                return(0x00, 0x20)
            }
            

            //
            // Equivalent code:
            //
            // for (uint256 i = 2; i < 2 + paddingLen; ) {
            //     if (decipher[i] != 0xff) {
            //         return false;
            //     }
            //     unchecked {
            //         i++;
            //     }
            // }
            //
            let _maxIndex := add(add(decipher, 34 /* 0x20+2 */), paddingLen)
            for {
                let i := add(decipher, 34) /* 0x20+2 */
            } lt(i, _maxIndex) {
                i := add(i, 1)
            } {
                if lt(byte(0, mload(i)), 0xff) {
                    mstore(0x00, false)
                    return(0x00, 0x20)
                }
            }

            //
            // Equivalent code:
            //
            // if (decipher[2 + paddingLen] != 0) {
            //     return false;
            // }
            //
            if gt(byte(0, mload(_maxIndex)), 0) {
                mstore(0x00, false)
                return(0x00, 0x20)
            }
        }

        // check digest algorithm
        if (digestAlgoWithParamLen == sha256ExplicitNullParamByteLen) {
            assembly ("memory-safe") {
                //
                // Equivalent code:
                //
                //    for (uint i = 0; i < digestAlgoWithParamLen; i++) {
                //        if (decipher[3 + paddingLen + i] != bytes1(sha256ExplicitNullParam[i])) {
                //            return false;
                //        }
                //    }
                //

                // load decipher[3 + paddingLen + 0]
                let _data := mload(
                    add(add(decipher, 35 /* 0x20+3 */), paddingLen)
                )
                // ensure that only the first `sha256ImplicitNullParamByteLen` bytes have data
                _data := and(_data, sha256ExplicitNullParamMask)
                // check that the data is equal to `sha256ExplicitNullParam`
                _data := xor(_data, sha256ExplicitNullParam)
                if gt(_data, 0) {
                    mstore(0x00, false)
                    return(0x00, 0x20)
                }
            }
        } else {
            assembly ("memory-safe") {
                //
                // Equivalent code:
                //
                //    for (uint i = 0; i < digestAlgoWithParamLen; i++) {
                //        if (decipher[3 + paddingLen + i] != bytes1(sha256ImplicitNullParam[i])) {
                //            return false;
                //        }
                //    }
                //

                // load decipher[3 + paddingLen + 0]
                let _data := mload(add(add(decipher, 35/* 0x20+3 */), paddingLen))
                // ensure that only the first `sha256ImplicitNullParamByteLen` bytes have data
                _data := and(_data, sha256ImplicitNullParamMask)
                // check that the data is equal to `sha256ImplicitNullParam`
                _data := xor(_data, sha256ImplicitNullParam)
                if gt(_data, 0) {
                    mstore(0x00, false)
                    return(0x00, 0x20)
                }
            }
        }

        // check digest
        assembly ("memory-safe") {
            //
            // Equivalent code:
            // if (
            //     decipher[3 + paddingLen + digestAlgoWithParamLen] != 0x04 ||
            //     decipher[4 + paddingLen + digestAlgoWithParamLen] != 0x20
            // ) {
            //     return false;
            // }

            if sub(
                and(
                    mload(
                        add(
                            add(add(decipher, 35 /* 0x20+3 */), paddingLen),
                            digestAlgoWithParamLen
                        )
                    ),
                    0xffff000000000000000000000000000000000000000000000000000000000000 /* 32bytes */
                ),
                0x0420000000000000000000000000000000000000000000000000000000000000 /* 32bytes */
                /*
                    0: 0x04
                    1: 0x20
                */
            ) {
                mstore(0x00, false)
                return(0x00, 0x20)
            }

            //
            // Equivalent code:
            //
            //    for (uint i = 0;i<_sha256.length;i++) {
            //        if (decipher[5+paddingLen+digestAlgoWithParamLen+i]!=_sha256[i]) {
            //            return false;
            //        }
            //    }
            //
            // load decipher[5 + paddingLen + digestAlgoWithParamLen + 0]
            let _data := mload(
                add(
                    add(add(add(decipher, 0x20), 5), paddingLen),
                    digestAlgoWithParamLen
                )
            )
            // check that the data is equal to `_sha256`
            _data := xor(_data, _sha256)
            if gt(_data, 0) {
                mstore(0x00, false)
                return(0x00, 0x20)
            }
        }

        return true;
    }

    /** @dev Verifies a PKCSv1.5 SHA256 signature
     * @param _data to verify
     * @param _s is the signature
     * @param _e is the exponent
     * @param _m is the modulus
     * @return 0 if success, >0 otherwise
     */
    function pkcs1Sha256Raw(
        bytes memory _data,
        bytes memory _s,
        bytes memory _e,
        bytes memory _m
    ) public view returns (bool) {
        return pkcs1Sha256(sha256(_data), _s, _e, _m);
    }
}
