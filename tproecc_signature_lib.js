/*jslint node: true */
'use strict';

var dstu4145_lib = require('./dstu4145ECC/dstu4145');
var asn1_lib = require('./asn1EncDec/asn1encdec');
var digest_lib = require('tproecc_digest_lib/tproecc_digest_lib');
var elliptic_lib = require('elliptic').ec;
var brorand_lib = require('brorand');


function TProEccSignatureException(message, stack) {
    this.message = message;
    if (stack !== undefined)
        this.stack = (new Error("[" + this.name + "] " + message)).stack + "\nCaused by:\n" + stack + "\n";
    else
        this.stack = (new Error("[" + this.name + "] " + message)).stack;
}
TProEccSignatureException.prototype = Object.create(Error.prototype);
TProEccSignatureException.prototype.constructor = TProEccSignatureException;
TProEccSignatureException.prototype.name = "TProEccSignatureException";


function TProEccSignature() {}

TProEccSignature._DSTU4145_CURVES = ["DSTU4145_233", "DSTU4145_307", "DSTU4145_431"];
TProEccSignature._NIST_CURVES = ["NIST_P256"];
TProEccSignature._NIST_CURVES_MAPPING = ["p256"];


TProEccSignature._isHexNumber = function (str) {
    return /^([0-9A-Fa-f][0-9A-Fa-f])+$/.test(str);
};

TProEccSignature._checkCurveSupported = function (funName, curveType, supportedCurves) {
    for (var index = 0; index < supportedCurves.length; index++) {
        if (curveType === supportedCurves[index]) return index;
    }
    throw new TProEccSignatureException(funName + " - curve type not supported:" + curveType);
};

TProEccSignature._generateKeyPairDSTU = function (curveType) {
    this._checkCurveSupported("generateKeyPair", curveType, this._DSTU4145_CURVES);
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
            throw new TProEccSignatureException("generateKeyPair - " + exc.message, exc.stack);
        } else
            throw new Error(exc);
    }
};

TProEccSignature._generateKeyPairNIST = function (curveType) {
    var curveId = this._checkCurveSupported("generateKeyPair", curveType, this._NIST_CURVES);
    var curveName = this._NIST_CURVES_MAPPING[curveId];
    try {
        var ec = new elliptic_lib(curveName);
        var keyPair = ec.genKeyPair();
        return {
            priv: keyPair.getPrivate('hex'),
            pub: keyPair.getPublic('hex')
        };
    } catch (exc) {
        throw new TProEccSignatureException("generateKeyPair - " + exc.message, exc.stack);
    }
};

TProEccSignature._verifySignatureDSTU = function (digestValue, curveType, publicKeyValue, signatureValue) {
    this._checkCurveSupported("verifySignature", curveType, this._DSTU4145_CURVES);

    try {
        var dstu = new dstu4145_lib(curveType);
        var keyBytes = dstu.getKeyBytes();
        var pubKey = asn1_lib.decodePublicKey(keyBytes, publicKeyValue);
        var publicKeyObj = dstu.decodePublicKeyXY(pubKey.x, pubKey.y);
        var sign = asn1_lib.decodeSignature(keyBytes, signatureValue);
        return dstu.verifyHexSignRS(publicKeyObj, digestValue, sign.r, sign.s);
    } catch (exc) {
        if (exc.name === "DSTU4145Exception" || exc.name === "ASN1EncDecException") {
            throw new TProEccSignatureException("verifySignature - " + exc.message, exc.stack);
        } else
            throw new Error(exc);
    }
};

TProEccSignature._verifySignatureNIST = function (digestValue, curveType, publicKeyValue, signatureValue) {
    var curveId = this._checkCurveSupported("verifySignature", curveType, this._NIST_CURVES);
    var curveName = this._NIST_CURVES_MAPPING[curveId];

    try {
        //decode ecc public key from hex representation
        var ec = new elliptic_lib(curveName);
        var publicKey = ec.keyFromPublic(publicKeyValue, 'hex');

        // check if decoded public key is valid
        var validationResult = publicKey.validate();
        if (validationResult.result === false)
            throw new TProEccSignatureException("verifySignature - " + validationResult.reason);

        // decode signature asn
        var keyBytes = ec.curve.p.byteLength();

        // just for checking - produces better error codes, that verify itself
        asn1_lib.decodeSignature(keyBytes, signatureValue);
        return publicKey.verify(digestValue, signatureValue);
    } catch (exc) {
        throw new TProEccSignatureException("verifySignature - " + exc.message, exc.stack);
    }
};

TProEccSignature._signDigestDSTU = function (curveType, digestType, digestValue, privateKeyValue) {
    this._checkCurveSupported("signDigest", curveType, this._DSTU4145_CURVES);
    try {
        var dstu = new dstu4145_lib(curveType);
        var keyBytes = dstu.getKeyBytes();
        var keyPair = dstu.generateKeyPair(privateKeyValue);
        var signature = dstu.sign(keyPair.privKey, digestValue);
        return asn1_lib.encodeSignature(keyBytes, signature.r, signature.s);
    } catch (exc) {
        if (exc.name === "DSTU4145Exception" || exc.name === "ASN1EncDecException") {
            throw new TProEccSignatureException("signDigest - " + exc.message, exc.stack);
        } else
            throw new Error(exc);
    }
};

TProEccSignature._signDigestNIST = function (curveType, digestType, digestValue, privateKeyValue) {
    var curveId = this._checkCurveSupported("signDigest", curveType, this._NIST_CURVES);
    var curveName = this._NIST_CURVES_MAPPING[curveId];

    try {
        //decode ecc public key from hex representation
        var ec = new elliptic_lib(curveName);
        var keyBytes = ec.curve.p.byteLength();
        var privKeyObj = ec.keyFromPrivate(privateKeyValue, 'hex');
        var signature = privKeyObj.sign(digestValue, { pers: brorand_lib(200)} );
        var r = signature.r.toString(16);
        var s = signature.s.toString(16);
        return asn1_lib.encodeSignature(keyBytes, r, s);
    } catch (exc) {
        throw new TProEccSignatureException("signDigest - " + exc.message, exc.stack);
    }
};

TProEccSignature._validatePublicKeyDSTU = function (curveType, publicKeyValue, popAlg, popInput, popResult) {
    this._checkCurveSupported("validatePublicKey", curveType, this._DSTU4145_CURVES);

    try {
        var dstu = new dstu4145_lib(curveType);
        var pubKey = asn1_lib.decodePublicKey(dstu.getKeyBytes(), publicKeyValue);
        dstu.decodePublicKeyXY(pubKey.x, pubKey.y);
    } catch (exc) {
        if (exc.name === "DSTU4145Exception" || exc.name === "ASN1EncDecException") {
            throw new TProEccSignatureException("validatePublicKey - " + exc.message, exc.stack);
        } else
            throw new Error(exc);
    }
};

TProEccSignature._validatePublicKeyNIST = function (curveType, publicKeyValue, popAlg, popInput, popResult) {
    var curveId = this._checkCurveSupported("validatePublicKey", curveType, this._NIST_CURVES);
    var curveName = this._NIST_CURVES_MAPPING[curveId];

    try {
        //decode ecc public key from hex representation
        var ec = new elliptic_lib(curveName);
        var publicKey = ec.keyFromPublic(publicKeyValue, 'hex');

        // check if decoded public key is valid
        var validationResult = publicKey.validate();
        if (validationResult.result === false)
            throw new TProEccSignatureException("validatePublicKey - " + validationResult.reason);
    } catch (exc) {
        throw new TProEccSignatureException("validatePublicKey - " + exc.message, exc.stack);
    }
};

/**************************/
/***   Public methods   ***/
/**************************/

TProEccSignature.generateKeyPair = function (curveType) {
    if (curveType === undefined)
        throw new TProEccSignatureException("generateKeyPair - curveType is undefined");

    if (curveType.startsWith("DSTU4145"))
        return this._generateKeyPairDSTU(curveType);
    else if (curveType.startsWith("NIST"))
        return this._generateKeyPairNIST(curveType);
    else
        throw new TProEccSignatureException("generateKeyPair - curve type not supported:" + curveType);
};

TProEccSignature.signDigest = function (curveType, digestType, digestValue, privateKeyValue) {
    if (curveType === undefined)
        throw new TProEccSignatureException("signDigest - curveType is undefined");
    if (digestType === undefined)
        throw new TProEccSignatureException("signDigest - digestType is undefined");

    if (digestValue === undefined)
        throw new TProEccSignatureException("signDigest - digestValue is undefined");
    if (!this._isHexNumber(digestValue)) throw new TProEccSignatureException("signDigest - digestValue is not a hex string");

    if (privateKeyValue === undefined)
        throw new TProEccSignatureException("signDigest - privateKeyValue is undefined");
    if (!this._isHexNumber(privateKeyValue)) throw new TProEccSignatureException("signDigest - privateKeyValue is not a hex string");

    var digestObj = new digest_lib();
    if (!digestObj.isDigestSupported(digestType))
        throw new TProEccSignatureException("signDigest - unsupported digest type:" + digestType);

    // TODO sprawdzenie czy digestType koresponduje z długością

    if (curveType.startsWith("DSTU4145"))
        return this._signDigestDSTU(curveType, digestType, digestValue, privateKeyValue);
    else if (curveType.startsWith("NIST"))
        return this._signDigestNIST(curveType, digestType, digestValue, privateKeyValue);
    else
        throw new TProEccSignatureException("signDigest - curve type not supported:" + curveType);
};

TProEccSignature.validatePublicKey = function (curveType, publicKeyValue, popAlg, popInput, popResult) {
    if (curveType === undefined)
        throw new TProEccSignatureException("validatePublicKey - curveType is undefined");

    if (publicKeyValue === undefined)
        throw new TProEccSignatureException("validatePublicKey - keyValue is undefined");
    if (!this._isHexNumber(publicKeyValue)) throw new TProEccSignatureException("validatePublicKey - publicKeyValue is not a hex string");

    if (popAlg === undefined)
        throw new TProEccSignatureException("validatePublicKey - popAlg is undefined");

    if (popInput === undefined)
        throw new TProEccSignatureException("validatePublicKey - popInput is undefined");
    if (!this._isHexNumber(popInput)) throw new TProEccSignatureException("validatePublicKey - popInput is not a hex string");

    if (popResult === undefined)
        throw new TProEccSignatureException("validatePublicKey - popResult is undefined");
    if (!this._isHexNumber(popResult)) throw new TProEccSignatureException("validatePublicKey - popResult is not a hex string");

    if (curveType.startsWith("DSTU4145"))
        this._validatePublicKeyDSTU(curveType, publicKeyValue, popAlg, popInput, popResult);
    else if (curveType.startsWith("NIST"))
        this._validatePublicKeyNIST(curveType, publicKeyValue, popAlg, popInput, popResult);
    else
        throw new TProEccSignatureException("validatePublicKey - curve type not supported:" + curveType);
};

TProEccSignature.calculateDigest = function (digestType, message) {
    if (digestType === undefined) throw new TProEccSignatureException("calculateDigest - digestType is undefined");
    if (message === undefined) throw new TProEccSignatureException("calculateDigest - message is undefined");

    var digestObj = new digest_lib();
    if (!digestObj.isDigestSupported(digestType))
        throw new TProEccSignatureException("calculateDigest - unsupported digest type:" + digestType);

    return digestObj.digestUTF8(digestType, message);
};

TProEccSignature.verifySignature = function (digestValue, curveType, publicKeyValue, signatureValue) {
    if (digestValue === undefined)
        throw new TProEccSignatureException("verifySignature - digestValue is undefined");
    if (!this._isHexNumber(digestValue)) throw new TProEccSignatureException("verifySignature - digestValue is not a hex string");


    if (curveType === undefined)
        throw new TProEccSignatureException("verifySignature - curveType is undefined");
    if (publicKeyValue === undefined)
        throw new TProEccSignatureException("verifySignature - publicKeyValue is undefined");
    if (!this._isHexNumber(publicKeyValue)) throw new TProEccSignatureException("verifySignature - publicKeyValue is not a hex string");

    if (signatureValue === undefined)
        throw new TProEccSignatureException("verifySignature - signatureValue is undefined");
    if (!this._isHexNumber(signatureValue)) throw new TProEccSignatureException("verifySignature - signatureValue is not a hex string");

    if (curveType.startsWith("DSTU4145"))
        return this._verifySignatureDSTU(digestValue, curveType, publicKeyValue, signatureValue);
    else
    if (curveType.startsWith("NIST"))
        return this._verifySignatureNIST(digestValue, curveType, publicKeyValue, signatureValue);
    else
        throw new TProEccSignatureException("verifySignature - curve type not supported:" + curveType);
};

module.exports = TProEccSignature;
