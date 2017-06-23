/*jslint node: true */

'use strict';
var dstu4145_lib = require('./dstu4145ECC/dstu4145');
var asn1_lib = require('./asn1EncDec/asn1encdec');
var digest_lib = require('tproecc_digest_lib/tproecc_digest_lib');

function TProEccSignLibException(message) {
    this.message = message;
    this.stack = (new Error("[" + this.name + "] " + message)).stack;
}
TProEccSignLibException.prototype = Object.create(Error.prototype);
TProEccSignLibException.prototype.constructor = TProEccSignLibException;
TProEccSignLibException.prototype.name = "TProEccSignLibException";




var example1 =


    {
        "tokenId": "43de32fa892d49c2",
        "pubKey": {
            "keyValue": "040191009210f1368ebd4d95d0f65c304ff0d8a0d230d1ab3358746bfee2dcf5faa39ee6bb5edf720791b1b2f74aa8c5faa9e98c9be8dfba57792c2dc0d177fae1150ec876a98e082654db5f89c68d",
            "curveType": "DSTU4145_307"
        },
        "pop": {
            "popAlg": "DSTU_KUPYNA",
            "popInput": "040191009210f1368ebd4d95d0f65c304ff0d8a0d230d1ab3358746bfee2dcf5faa39ee6bb5edf720791b1b2f74aa8c5faa9e98c9be8dfba57792c2dc0d177fae1150ec876a98e082654db5f89c68d",
            "popResult": "307002360cfa46fdb4adec65f835e1586930e1121c704c60067820a2edd0a18a3389ec6daaeb53189c3c6f95da2cece5743a123af8dc38ebc2280236084a04b214793a7ac4aaec555e010091e8f39f0e8ee876854e08037402b30ba53d0c097137aff5fb397e9eb40431bf17cbb4f0fd5c48"
        }
    }


var example2 = {
    "tokenId": "43de32fa892d49c2",
    "signature": {
        "digestType": "KUPYNA_256",
        "curveType": "DSTU4145_307",
        "signatureValue": "3052022701ad72453693afd3e0d7ca8e45b2f7edb57b98012c501faca59d571d2329ba6e0651426a9916f30227006efc02b282dd50cf87a1e008abb8c6963ec419b89729845dfc6b3e3b1fbf3965b204d5273d14"
    }
}


function validatePop() {

}

function isDSTUCurveSupported(curveType) {
    var supportedCurves = ["DSTU4145_233", "DSTU4145_307", "DSTU4145_433"];
    for (var index = 0; index < supportedCurves.length; index++) {
        if (curveType === supportedCurves[index]) return true;
    }
    return false;
}

function validatePublicKey(curveType, publicKeyValue, popAlg, popInput, popResult) {
    if (curveType === undefined) throw new TProEccSignLibException("validatePublicKey - curveType is null");
    if (publicKeyValue === undefined) throw new TProEccSignLibException("validatePublicKey - keyValue is null");
    if (popAlg === undefined) throw new TProEccSignLibException("validatePublicKey - popAlg is null");
    if (popInput === undefined) throw new TProEccSignLibException("validatePublicKey - popInput is null");
    if (popResult === undefined) throw new TProEccSignLibException("validatePublicKey - popResult is null");

    if (curveType.startsWith("DSTU4145")) {
        if (!isDSTUCurveSupported(curveType)) throw new TProEccSignLibException("curve type not supported");

        try {
            var dstu = new dstu4145_lib(curveType);
            var pubKey = asn1_lib.decodePublicKey(dstu.getKeyBytes(), publicKeyValue);
            dstu.decodePublicKeyXY(pubKey.x, pubKey.y);
        } catch (exc) {
            if (exc.name === "DSTU4145Exception" || exc.name === "ASN1EncDecException") {
                throw new TProEccSignLibException(exc.message);
            } else
                throw new Error(exc);
        }

    }
}

function calculateDigest(digestType, message) {
    if (digestType === undefined) throw new TProEccSignLibException("calculateDigest - digestType is undefined");
    if (message === undefined) throw new TProEccSignLibException("calculateDigest - message is undefined");
    
        var digestObj = new digest_lib();
    if (!digestObj.isDigestSupported(digestType))
        throw new TProEccSignLibException("calculateDigest - unsupported digest type:" + digestType);

    return digestObj.digestUTF8(digestType, message);
}

function verifySignature(digestValue, curveType, publicKeyValue, signatureValue) {
    if (digestValue === undefined) throw new TProEccSignLibException("verifySignature - digestValue is undefined");
    if (curveType === undefined) throw new TProEccSignLibException("verifySignature - curveType is undefined");
    if (publicKeyValue === undefined) throw new TProEccSignLibException("verifySignature - publicKeyValue is undefined");
    if (signatureValue === undefined) throw new TProEccSignLibException("verifySignature - signatureValue is undefined");

    var verifyResult = false;
    if (curveType.startsWith("DSTU4145")) {
        if (!isDSTUCurveSupported(curveType)) throw new TProEccSignLibException("curve type not supported");

        try {
            var dstu = new dstu4145_lib(curveType);
            var keyBytes = dstu.getKeyBytes();
            var pubKey = asn1_lib.decodePublicKey(keyBytes, publicKeyValue);
            var publicKeyObj = dstu.decodePublicKeyXY(pubKey.x, pubKey.y);
            var sign = asn1_lib.decodeSignature(keyBytes, signatureValue);
            verifyResult = dstu.verifyHexSignRS(publicKeyObj, digestValue, sign.r, sign.s);
        } catch (exc) {
            if (exc.name === "DSTU4145Exception" || exc.name === "ASN1EncDecException") {
                throw new TProEccSignLibException(exc.message);
            } else
                throw new Error(exc);
        }
    }
    return verifyResult;
}

console.log(digest_lib);

var dig = calculateDigest("SHA3_256", "asdf");
console.log(dig);
var digest = "996899f2d7422ceaf552475036b2dc120607eff538abf2b8dff471a98a4740c6";
var result = verifySignature(digest, example2.signature.curveType, example1.pubKey.keyValue, example2.signature.signatureValue);
console.log(result);

//validatePublicKey(example1.pubKey.curveType, example1.pubKey.keyValue, example1.pop.popAlg, example1.pop.popInput, example1.pop.popResult);


//console.log(a);