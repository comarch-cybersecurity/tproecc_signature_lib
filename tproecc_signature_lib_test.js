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

var example3 = {
    "tokenID": "0123A137D9999A97EE",
    "pubKey": {
        "keyValue": "0409c0d2cce0226d53cb0765d2524ce8b3565010d8fc168beed6a89d5d68598cc653f5cee4f2830ad46c752e3bb61584ec27939445df3f80e1f71ace4bd157cbc6",
        "curveType": "NIST_P256"
    },
    "pop": {
        "popAlg": "NIST_SHA",
        "popInput": "0000000123a137d9999a97ee566aa5d703dd2e9d253046e36016a2619f8164ce54bec6f8d571695f32f3a166",
        "popResult": "304502200e81ddfe5207d7708221bb5178916020051e7523e387a38d461c52402a137b6c022100a0f92d3a5831c1aa3e44f7cc224f61cde3efccc7c44c2821180ca3049fb353e3"
    }
};

var example4 = {
    "tokenID": "0123A137D9999A97EE",
    "signature": {
        "digestType": "SHA 256",
        "curveType": "NIST_P256",
        "signatureValue": "304402207e88082fe76f5e454fc9238ec1a36fd70976d227a333dc6105b4d89aa6da16fa0220292fbd5f3e05117b12213faf244d507040b6af61b21d4179daa851a86217daf4"
    }
};

function testNIST() {
    tProSign.validatePublicKey(example3.pubKey.curveType, example3.pubKey.keyValue, example3.pop.popAlg, example3.pop.popInput, example3.pop.popResult);
    var digest = "c962d174df057264b67a5fe7124387a6daa6fb665e0d6f6ebef29987877737b0";
    var result = tProSign.verifySignature(digest, example4.signature.curveType, example3.pubKey.keyValue, example4.signature.signatureValue);

    for (var i = 0; i < 200; i++) {
        console.log("iter:" + i);
        var keys = tProSign.generateKeyPair("NIST_P256");
        tProSign.validatePublicKey("NIST_P256", keys.pub, example3.pop.popAlg, example3.pop.popInput, example3.pop.popResult);

        var sign = tProSign.signDigest("NIST_P256", "SHA3_512", digest, keys.priv);
        console.log(sign);
        result = tProSign.verifySignature(digest, "NIST_P256", keys.pub, sign);
    }

    console.log("nist verify result:" + result);
}


function testDSTU() {
    var dig = tProSign.calculateDigest("SHA3_256", "asdf");
    console.log(dig);
    var digest = "996899f2d7422ceaf552475036b2dc120607eff538abf2b8dff471a98a4740c6";
    var result = tProSign.verifySignature(digest, example2.signature.curveType, example1.pubKey.keyValue, example2.signature.signatureValue);
    console.log(result);

    tProSign.validatePublicKey(example1.pubKey.curveType, example1.pubKey.keyValue, example1.pop.popAlg, example1.pop.popInput, example1.pop.popResult);

    var keys = tProSign.generateKeyPair("DSTU4145_431");
    var sign = tProSign.signDigest("DSTU4145_431", "ASDF", digest, keys.priv);
    console.log(sign);
}

testNIST();
//testDSTU();