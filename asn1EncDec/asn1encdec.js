/*jslint node: true */

'use strict';

function ASN1EncDecException(message) {
    this.message = message;
    this.stack = (new Error("[" + this.name + "] " + message)).stack;
}
ASN1EncDecException.prototype = Object.create(Error.prototype);
ASN1EncDecException.prototype.constructor = ASN1EncDecException;
ASN1EncDecException.prototype.name = "ASN1EncDecException";


function ASN1EncDec() {

}

ASN1EncDec.decodePublicKey = function (keyBytes, encodedPublicKeyHex) {
    var publicKey = new Buffer(encodedPublicKeyHex, "hex");
    if (publicKey.length === 0) throw new ASN1EncDecException("decodePublicKey - encodedPublicKeyHex is not hex string");
    if (publicKey[0] !== 0x04) throw new ASN1EncDecException("decodePublicKey - invalid asn prefix - expected 0x40");
    if (publicKey.length != keyBytes * 2 + 1) throw new ASN1EncDecException("decodePublicKey - invalid key len - expected:" + keyBytes);

    var xHex = publicKey.slice(1, 1 + keyBytes).toString('hex');
    var yHex = publicKey.slice(1 + keyBytes, 1 + 2 * keyBytes).toString('hex');
    return {
        "x": xHex,
        "y": yHex
    };
};

ASN1EncDec.decodeSignature = function (keyBytes, encodedSignatureHex) {
    var signParams = {};

    var signature = new Buffer(encodedSignatureHex, "hex");
    if (signature.length === 0) throw new ASN1EncDecException("decodeSignature - encodedSignatureHex is not hex string");

    var startOffset = 0;
    if (signature[startOffset++] != 0x30) throw new ASN1EncDecException("decodeSignature - invalid asn prefix - expected 0x30");
    var signLen = signature[startOffset++];
    if (signLen != signature.length - 2)
        throw new ASN1EncDecException("decodeSignature - asn len differs from actual len");

    var minLen = keyBytes * 2 + 4;
    var maxLen = minLen + 2;

    if (signLen > maxLen || signLen < minLen)
        throw new ASN1EncDecException("decodeSignature - invalid size - found:" + signLen + " expected:" + minLen);

    for (var index = 0; index < 2; index++) {
        if (signature[startOffset] !== 0x02)
            throw new ASN1EncDecException("invalid asn integer prefix - expected 0x02 at location:" + startOffset);

        var len = signature[++startOffset];
        if (len < keyBytes || len > keyBytes + 1)
            throw new ASN1EncDecException("decodeSignature - invalid asn len of integer at:" + startOffset + " expected:<" + keyBytes + "," + (keyBytes + 1) + "> found:" + len);

        startOffset++;
        var number = signature.slice(startOffset, startOffset + len).toString('hex');
        startOffset += len;

        if (index === 0) signParams.r = number;
        else
            signParams.s = number;

    }
    return signParams;
};

ASN1EncDec._convertASNSignatureParam = function (keyBytes, signParam) {
    // add leading zeros

     if (signParam.length > keyBytes) {
        throw new Error("invalid signature parameter size");
    }

    var buf = Buffer.alloc(keyBytes);
    signParam.copy(buf, keyBytes - signParam.length, 0, signParam.length);

    var hexParam = buf.toString("hex");
    if ((buf[0] & 0x80) === 0x80) {
        hexParam = "00" + hexParam; // add one byte prefix for negative number 
    }
    return "02" + ASN1EncDec._addASNLenPrefix(hexParam);
}

ASN1EncDec._addASNLenPrefix = function (dataHex) {
    var lenHex = (dataHex.length / 2);
    lenHex = lenHex.toString(16);
    if (lenHex.length === 1) {
        return "0" + lenHex + dataHex;
    }
    return lenHex + dataHex;
};

ASN1EncDec.encodeSignature = function (keyBytes, rHex, sHex) {
    var r = new Buffer(rHex, 'hex');
    var s = new Buffer(sHex, 'hex');
    return "30" + ASN1EncDec._addASNLenPrefix(ASN1EncDec._convertASNSignatureParam(keyBytes, r) +
        ASN1EncDec._convertASNSignatureParam(keyBytes, s));
}

module.exports = ASN1EncDec;