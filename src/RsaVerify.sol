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

library RsaVerify {

    /** @dev Verifies a PKCSv1.5 SHA256 signature
      * @param _sha256 is the sha256 of the data
      * @param _s is the signature
      * @param _e is the exponent
      * @param _m is the modulus
      * @return 0 if success, >0 otherwise
    */    
    function pkcs1Sha256(
        bytes32 _sha256,
        bytes memory _s, bytes memory _e, bytes memory _m
    ) public view returns (bool) {
        
        uint8[17] memory sha256ExplicitNullParam = [
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00
        ];

        uint8[15] memory sha256ImplicitNullParam = [
            0x30,0x2f,0x30,0x0b,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01
        ];
        
        uint i;

        /// decipher
        bytes memory input = bytes.concat(
            bytes32(_s.length),
            bytes32(_e.length),
            bytes32(_m.length),
            _s,_e,_m
        );
        uint inputlen = input.length;

        uint decipherlen = _m.length;
        bytes memory decipher = new bytes(decipherlen);
        assembly {
            pop(staticcall(sub(gas(), 2000), 5, add(input,0x20), inputlen, add(decipher,0x20), decipherlen))
	    }

        /// 0x00 || 0x01 || PS || 0x00 || DigestInfo
        /// PS is padding filled with 0xff
        //  DigestInfo ::= SEQUENCE {
        //     digestAlgorithm AlgorithmIdentifier,
        //       [optional algorithm parameters]
        //     digest OCTET STRING
        //  }

        bool hasNullParam;
        uint hashAlgoWithParamLen;

        if (uint8(decipher[decipherlen-50])==0x31) {
            hasNullParam = true;
             hashAlgoWithParamLen = sha256ExplicitNullParam.length;
        } else if  (uint8(decipher[decipherlen-48])==0x2f) {
            hasNullParam = false;
            hashAlgoWithParamLen = sha256ImplicitNullParam.length;
        } else {
            return false;
        }

        uint256 paddingLen = decipherlen - 5 - hashAlgoWithParamLen -  32 ;

        if (decipher[0] != 0 || decipher[1] != 0x01) {
            return false;
        }
        for (i = 2;i<2+paddingLen;i++) {
            if (decipher[i] != 0xff) {
                return false;
            }
        }
        if (decipher[2+paddingLen] != 0) {
            return false;
        }

        if (hashAlgoWithParamLen == sha256ExplicitNullParam.length) {
            for (i = 0;i<hashAlgoWithParamLen;i++) {
                if (decipher[3+paddingLen+i]!=bytes1(sha256ExplicitNullParam[i])) {
                    return false;
                }
            }
        } else {
            for (i = 0;i<hashAlgoWithParamLen;i++) {
                if (decipher[3+paddingLen+i]!=bytes1(sha256ImplicitNullParam[i])) {
                    return false;
                }
            }
        }

        for (i = 0;i<_sha256.length;i++) {
            if (decipher[3+2+paddingLen+hashAlgoWithParamLen+i]!=_sha256[i]) {
                return false;
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
        bytes memory _s, bytes memory _e, bytes memory _m
    ) public view returns (bool) {
        return pkcs1Sha256(sha256(_data),_s,_e,_m);
    }

}
