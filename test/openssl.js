/* global artifacts */
/* global contract */
/* global web3 */
/* global assert */

const SolRsaVerify = artifacts.require("../contracts/SolRsaVerify.sol");

contract("SolRsaVerify-openssl", (accounts) => {

    let v

    beforeEach(async () => {
        v = await SolRsaVerify.new();
    });

    /*
        > openssl genrsa -out private.pem 1024

        > cat private.pem
        -----BEGIN RSA PRIVATE KEY-----
        MIICXAIBAAKBgQDfPt3gCblrxbA7SL1z/nCjrSDq9iTQ3BuhIaRcxzmJN0G3z4Ks
        8ckVc+yCZlOJl8Zpl2AUjeV+VJgxkeygF29RjlR7hf4Lt9nhUN8Z7uc0z1M4IZx/
        j3sTs59ThBefYsE15UTLcL51BXUfNFaOBpgQla7sTzqIdjlxij4R1IwkDQIDAQAB
        AoGAQEoBaThDrnaSpq/u5w158Ji15xQVTBRm3IMsqw8wUYSZJ07Z6eYDK2tjy7We
        DvynRdcy8xhd44CHB5dnVj8JbiBX26i05fkOy3vtWtWWPQi+lIBLPOYiJA3Jeu01
        KrRUKpDjDx9jz5bV3RQNIKhy6oWAmzqZw84w2H5Yu1GeNl0CQQD2NzMllvxh1b03
        2CF0KNvEJo83VmpGoNNnljKaMwuDXeog+NGEkOL89iBZLmaErdaUIKXMi7rKBHTe
        zc4KoeMrAkEA6B388AOtofBiS0kLumLxW6S27cbjOiJ6kgi2QuoZeYjwP1Sd2vBJ
        d/0ooqwO2m2ZBMhHvfWJNsj97bX9d2VZpwJBAK9Ruv/HNUtM8QF0ys110pcnhc83
        n1FPb3lRQBMAye/uzapQwpAMwzSw5XPbUHClgCfV33l4/baf2cBU96QmhiUCQAqq
        9ikBwkUjCyFypftW+MjBdTbQYTkWxJNZmybQI4OWa5Q9i1O4n2fIVsnDJpubVeEG
        Y2Wzly7RZfo61v9ZxRkCQDwTiiLUD7w6IE9CHhz6j1yI6P1Nn+wuymu7YMXG0zjs
        H6knPQhmeq6EXguCWPVvCIGbHZn16g+s9jkUEq48V+Y=
        -----END RSA PRIVATE KEY-----

        > openssl rsa -in private.pem -outform der -pubout -out public.pem

        # addd -n to echo to remove final carriage return
        > echo -n "hello world" | openssl dgst -sha256 -sign private.pem -out | xxd -p | tr -d \\n

        079bed733b48d69bdb03076cb17d9809072a5a765460bc72072d687dba492afe951d75b814f561f253ee5cc0f3d703b6eab5b5df635b03a5437c0a5c179309812f5b5c97650361c645bc99f806054de21eb187bc0a704ed38d3d4c2871a117c19b6da7e9a3d808481c46b22652d15b899ad3792da5419e50ee38759560002388

        # extract the public n from the public key
        > openssl asn1parse -inform TXT -i -in public.pem -strparse 18
            0:d=0  hl=3 l= 137 cons: SEQUENCE
            3:d=1  hl=3 l= 129 prim:  INTEGER           :DF3EDDE009B96BC5B03B48BD73FE70A3AD20EAF624D0DC1BA121A45CC739893741B7CF82ACF1C91573EC8266538997C6699760148DE57E54983191ECA0176F518E547B85FE0BB7D9E150DF19EEE734CF5338219C7F8F7B13B39F5384179F62C135E544CB70BE7505751F34568E06981095AEEC4F3A887639718A3E11D48C240D
          135:d=1  hl=2 l=   3 prim:  INTEGER           :010001
        
        # get the `e`=010001 and `n` DF..0D
    */

    it("openssl generation test", async () => {
        const e   = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001"
        const Msg = web3.utils.asciiToHex("hello world")
        const S   = "079bed733b48d69bdb03076cb17d9809072a5a765460bc72072d687dba492afe951d75b814f561f253ee5cc0f3d703b6eab5b5df635b03a5437c0a5c179309812f5b5c97650361c645bc99f806054de21eb187bc0a704ed38d3d4c2871a117c19b6da7e9a3d808481c46b22652d15b899ad3792da5419e50ee38759560002388"
        const nn  = "DF3EDDE009B96BC5B03B48BD73FE70A3AD20EAF624D0DC1BA121A45CC739893741B7CF82ACF1C91573EC8266538997C6699760148DE57E54983191ECA0176F518E547B85FE0BB7D9E150DF19EEE734CF5338219C7F8F7B13B39F5384179F62C135E544CB70BE7505751F34568E06981095AEEC4F3A887639718A3E11D48C240D"

        assert.equal((await v.pkcs1Sha256VerifyRaw(Msg,"0x"+S,"0x"+e,"0x"+nn)).toNumber(),0)
    });


});




