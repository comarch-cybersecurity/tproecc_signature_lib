/*jslint node: true */
'use strict';

var dstu4145_lib = require('./dstu4145ECC/dstu4145');
var asn1_lib = require('./asn1EncDec/asn1encdec');
var digest_lib = require('tproecc_digest_lib/tproecc_digest_lib');

function TProEccSignatureException(message, stack) {
    this.message = message;
    this.stack = (new Error("[" + this.name + "] " + message)).stack+"\nCaused by:\n"+stack+"\n";
}
TProEccSignatureException.prototype = Object.create(Error.prototype);
TProEccSignatureException.prototype.constructor = TProEccSignatureException;
TProEccSignatureException.prototype.name = "TProEccSignatureException";


function TProEccSignature() {}

TProEccSignature._checkCurveSupportedDSTU = function (curveType) {
    var supportedCurves = ["DSTU4145_233", "DSTU4145_307", "DSTU4145_431"];
    for (var index = 0; index < supportedCurves.length; index++) {
        if (curveType === supportedCurves[index]) return;
    }
    throw new TProEccSignatureException("curve type not supported:" + curveType);
};

TProEccSignature._generateKeyPairDSTU = function (curveType) {
    this._checkCurveSupportedDSTU(curveType);
    try {
        var dstu = new dstu4145_lib(curveType);
        var keyPair = dstu.generateKeyPair();
        var privKeyHex = dstu.encodePrivateKey(keyPair.privKey);
        var pubKeyHex = dstu.encodePublicKey(keyPair.pubKey);
        return {
            pub: pubKeyHex,
            priv: privKeyHex
        };
    } catch (exc) {
        if (exc.name === "DSTU4145Exception" || exc.name === "ASN1EncDecException") {
            throw new TProEccSignatureException(exc.message, exc.stack);
        } else
            throw new Error(exc);
    }
}

TProEccSignature.generateKeyPair = function (curveType) {
    if (curveType === undefined)
        throw new TProEccSignatureException("generateKeyPair - curveType is undefined");

    if (curveType.startsWith("DSTU4145")) {
        return this._generateKeyPairDSTU(curveType);
    } else
        throw new TProEccSignatureException("curve type not supported:" + curveType);
}

TProEccSignature._signDigestDSTU = function (curveType, digestType, digestValue, privateKeyValue) {
    this._checkCurveSupportedDSTU(curveType);
    try {
        var dstu = new dstu4145_lib(curveType);
        var keyPair = dstu.generateKeyPair(privateKeyValue);
        var signature = dstu.sign(keyPair.privKey, digestValue);

        console.log(signature);
        return signature;
    } catch (exc) {
        if (exc.name === "DSTU4145Exception" || exc.name === "ASN1EncDecException") {
            throw new TProEccSignatureException(exc.message, exc.stack);
        } else
            throw new Error(exc);
    }

}


TProEccSignature.signDigest = function (curveType, digestType, digestValue, privateKeyValue) {

// TODO sprawdzenie parametrów undefined

    if (curveType === undefined)
        throw new TProEccSignatureException("generateKeyPair - curveType is undefined");

// TODO sprawdzenie czy digestType koresponduje z długością

    if (curveType.startsWith("DSTU4145")) {
        return this._signDigestDSTU(curveType, digestType, digestValue, privateKeyValue);
    } else
        throw new TProEccSignatureException("curve type not supported:" + curveType);
}


TProEccSignature._validatePublicKeyDSTU = function (curveType, publicKeyValue, popAlg, popInput, popResult) {
    this._checkCurveSupportedDSTU(curveType);

    try {
        var dstu = new dstu4145_lib(curveType);
        var pubKey = asn1_lib.decodePublicKey(dstu.getKeyBytes(), publicKeyValue);
        dstu.decodePublicKeyXY(pubKey.x, pubKey.y);
    } catch (exc) {
        if (exc.name === "DSTU4145Exception" || exc.name === "ASN1EncDecException") {
            throw new TProEccSignatureException(exc.message, exc.stack);
        } else
            throw new Error(exc);
    }
}

TProEccSignature.validatePublicKey = function (curveType, publicKeyValue, popAlg, popInput, popResult) {
    if (curveType === undefined)
        throw new TProEccSignatureException("validatePublicKey - curveType is undefined");
    if (publicKeyValue === undefined)
        throw new TProEccSignatureException("validatePublicKey - keyValue is undefined");
    if (popAlg === undefined)
        throw new TProEccSignatureException("validatePublicKey - popAlg is undefined");
    if (popInput === undefined)
        throw new TProEccSignatureException("validatePublicKey - popInput is undefined");
    if (popResult === undefined)
        throw new TProEccSignatureException("validatePublicKey - popResult is undefined");

    if (curveType.startsWith("DSTU4145")) {
        this._validatePublicKeyDSTU(curveType, publicKeyValue, popAlg, popInput, popResult);
    } else
        throw new TProEccSignatureException("curve type not supported:" + curveType);

};

TProEccSignature.calculateDigest = function (digestType, message) {
    if (digestType === undefined) throw new TProEccSignatureException("calculateDigest - digestType is undefined");
    if (message === undefined) throw new TProEccSignatureException("calculateDigest - message is undefined");

    var digestObj = new digest_lib();
    if (!digestObj.isDigestSupported(digestType))
        throw new TProEccSignatureException("calculateDigest - unsupported digest type:" + digestType);

    return digestObj.digestUTF8(digestType, message);
};

TProEccSignature._verifySignatureDSTU = function (digestValue, curveType, publicKeyValue, signatureValue) {
    this._checkCurveSupportedDSTU(curveType);

    try {
        var dstu = new dstu4145_lib(curveType);
        var keyBytes = dstu.getKeyBytes();
        var pubKey = asn1_lib.decodePublicKey(keyBytes, publicKeyValue);
        var publicKeyObj = dstu.decodePublicKeyXY(pubKey.x, pubKey.y);
        var sign = asn1_lib.decodeSignature(keyBytes, signatureValue);
        return dstu.verifyHexSignRS(publicKeyObj, digestValue, sign.r, sign.s);
    } catch (exc) {
        if (exc.name === "DSTU4145Exception" || exc.name === "ASN1EncDecException") {
            throw new TProEccSignatureException(exc.message);
        } else
            throw new Error(exc);
    }
}

TProEccSignature.verifySignature = function (digestValue, curveType, publicKeyValue, signatureValue) {
    if (digestValue === undefined)
        throw new TProEccSignatureException("verifySignature - digestValue is undefined");
    if (curveType === undefined)
        throw new TProEccSignatureException("verifySignature - curveType is undefined");
    if (publicKeyValue === undefined)
        throw new TProEccSignatureException("verifySignature - publicKeyValue is undefined");
    if (signatureValue === undefined)
        throw new TProEccSignatureException("verifySignature - signatureValue is undefined");

    if (curveType.startsWith("DSTU4145"))
        return this._verifySignatureDSTU(digestValue, curveType, publicKeyValue, signatureValue);
    else
        throw new TProEccSignatureException("curve type not supported:" + curveType);


};

module.exports = TProEccSignature;