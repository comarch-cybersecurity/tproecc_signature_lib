/*jslint node: true */
'use strict';

var tProSign = require("./tproecc_signature_lib");

//var tProSign = new tpro_sign_lib();



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
    };


var example2 = {
    "tokenId": "43de32fa892d49c2",
    "signature": {
        "digestType": "KUPYNA_256",
        "curveType": "DSTU4145_307",
        "signatureValue": "3052022701ad72453693afd3e0d7ca8e45b2f7edb57b98012c501faca59d571d2329ba6e0651426a9916f30227006efc02b282dd50cf87a1e008abb8c6963ec419b89729845dfc6b3e3b1fbf3965b204d5273d14"
    }
};



var dig = tProSign.calculateDigest("SHA3_256", "asdf");
console.log(dig);
var digest = "996899f2d7422ceaf552475036b2dc120607eff538abf2b8dff471a98a4740c6";
var result = tProSign.verifySignature(digest, example2.signature.curveType, example1.pubKey.keyValue, example2.signature.signatureValue);
console.log(result);

tProSign.validatePublicKey(example1.pubKey.curveType, example1.pubKey.keyValue, example1.pop.popAlg, example1.pop.popInput, example1.pop.popResult);

var keys = tProSign.generateKeyPair("DSTU4145_431");
tProSign.signDigest( "DSTU4145_431", "ASDF", digest, keys.priv);
console.log(keys);