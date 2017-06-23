// jshint esversion:6

'use strict';
const EC_lib = require('elliptic').ec;
const crypto_lib = require('crypto');
const ec = new EC_lib('p256');

/* TProEcc server side tpro integration class */
class TProEcc {
    /**
     * @typedef {Object} ValidatePublicKeyResult
     * @property {KeyPair} publicKey PublicKey object representation or null
     * @property {Error} err Error object or null if not error
     */

    hexToArray(hexString) {
        var value = [];
        for (var i = 0; i < hexString.length; i += 2) {
            value.push(parseInt(hexString[i] + hexString[i + 1], 16));
        }
        return value;
    }

    decodeSignature(signHex) {
		console.log("s:"+signHex);
        var pos = 0;
        var signArr = this.hexToArray(signHex);
        if (signArr[pos++] != 0x30) return null;
        var signatureLen = signArr[pos++];
        var newSignHex = signHex.substring(0, signatureLen*2 + 4);
		return newSignHex;
        console.log("s:"+newSignHex);
    }

    /**
     *  @param {string} publicKeyHex - ECC public key string representation (hex digits)
     *  @return {{publicKey:{KeyPair}, err:string}}
     */
    validatePublicKey(publicKeyHex) {
        var publicKey;
        try {
            //decode ecc public key from hex representation
            publicKey = ec.keyFromPublic(publicKeyHex, 'hex');

            // check if decoded public key is valid
            var validationResult = publicKey.validate();
            if (validationResult.result === false)
                return {
                    publicKey: null,
                    err: validateResult.reason
                };
        } catch (err) {
            return {
                publicKey: null,
                err: err.message
            };
        }
        return {
            publicKey: publicKey,
            err: null
        };
    }

    rand() {
        return crypto_lib.randomBytes(32).toString('hex');
    }

    verifySignature(publicKeyObj, messageDigest, signatureOrig) {
        var signature = this.decodeSignature(signatureOrig);
        if (publicKeyObj.constructor.name != 'KeyPair')
            return {
                result: false,
                err: 'Invalid PublicKey object'
            };

        try {
            return {
                result: publicKeyObj.verify(messageDigest, signature),
                err: null
            };
        } catch (err) {
            return {
                result: false,
                err: err.message
            };
        }
    }

}

module.exports = TProEcc;
