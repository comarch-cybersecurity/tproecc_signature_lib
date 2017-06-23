/*jslint node: true */
'use strict';

var dstu4145_lib = require('./dstu4145');
var asn1_lib = require('../asn1EncDec/asn1encdec');

function performSignTest(dstuObj, param_D, param_H, param_E, param_R, param_S) {
  var keyPair = dstuObj.generateKey(param_D);
  var result = dstuObj.fixedSign(keyPair.privKey, param_H, param_E);
  console.log(result);

  if (result.r !== param_R.toLowerCase() || result.s !== param_S.toLowerCase()) {
    console.log("false");
    throw new Error("performSignTest");
  } else {
    console.log("true");
    return true;
  }
}

function testCurve167() {
  console.log("Test Curve 167");
  var dstu = new dstu4145_lib("DSTU4145_167");
  var testVector167_D = "15161718191a1b1c1d1e1f20212223242511121314";
  var testVector167_H = "ffffffffffffffffffffffffffffffffffffffffffffffffffff";
  var testVector167_E = "1FFFFFFFFFFFFFFFFFFFFFB12EBCC7D7F29FF7701F";
  var testVector167_R = "1180853a7d71021e2e6f50bab1312acf8292f182a0";
  var testVector167_S = "2630a06bab499fbfbbb0a144aa2e43a999de344062";
  performSignTest(dstu, testVector167_D, testVector167_H, testVector167_E, testVector167_R, testVector167_S);
  console.log();
}

function testCurve233() {
  console.log("Test Curve 233");
  var dstu = new dstu4145_lib("DSTU4145_233");

  var testVector233_D = "0000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1";
  var testVector233_H = "4277910c9aaee486883a2eb95b7180166ddf73532eeb76edaef52247ff";
  var testVector233_E = "001025e40bd97db012b7a1d79de8e12932d247f61c6000000000000000";
  var testVector233_R = "00DD01CCC18C1C1DC9CF6F1C9BA8D254006AC498D0808D0CE8C5E0EF03ED";
  var testVector233_S = "0031075E8D11DFC5DA3EE5A2CD7D2CF6DCFD83A54E858D6B4B89D18CD135";
  performSignTest(dstu, testVector233_D, testVector233_H, testVector233_E, testVector233_R, testVector233_S);
  console.log();
}

function testCurve307() {
  console.log("Test Curve 307");
  var dstu = new dstu4145_lib("DSTU4145_307");

  var testVector307_D = "0212223242526234728292a2b6ef539a82ace2c31415161718191a1b1c1d1e1f20212223242526";
  var testVector307_H = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  var testVector307_E = "001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFfffffffffffffffffffffffffffffffffffff";
  var testVector307_R = "01b6858844ca75395d8791f413b4d9ba8edc97e22a906efa6c5d141e6f266e3c5b69fddd418cf4";
  var testVector307_S = "008390272d7c4a31a9246153906816776a6667341028ca89b41a93f395d01024b66a3a660103fe";
  performSignTest(dstu, testVector307_D, testVector307_H, testVector307_E, testVector307_R, testVector307_S);
  console.log();
}

function testCurve431() {
  console.log("Test Curve 431");
  var dstu = new dstu4145_lib("DSTU4145_431");
  var testVector431_D = "3f01b203d405e60708c90a2b0c3d0e1f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435";
  var testVector431_H = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  var testVector431_E = "1fFfFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  var testVector431_R = "0cc279965f960d68fffa67ee57a1c0e48822112cd626926bca7f10098b32c49c51f1179b8d9431925203288f97b92f2814b483a03a9c";
  var testVector431_S = "180e2457c5631d6e164a9d04390cbfbb7f93eccfb26dd3c70e107a25e11a5a9bdde3ba5262c5b06c816a6ef43654a4923eae303e3600";
  performSignTest(dstu, testVector431_D, testVector431_H, testVector431_E, testVector431_R, testVector431_S);
  console.log();
}


function performTestSignatureVerify(curve) {
  for (var i = 0; i < 10; i++) {
    console.log("Test sign verify " + curve + ":" + (i + 1));
    var dstuObj = new dstu4145_lib("DSTU4145_" + curve);

    var hashHex = "3467546892126543236934675468921265432369ff77aaccddeeff99"
    var keyPair = dstuObj.generateKey();
    var result = dstuObj.sign(keyPair.privKey, hashHex);
    var encodedSignature = asn1_lib.encodeSignature(dstuObj.getKeyBytes(), result.r, result.s);
    console.log(encodedSignature);
               var sign = asn1_lib.decodeSignature(dstuObj.getKeyBytes(), encodedSignature);
    var        verifyResult = dstuObj.verifyHexSignRS(keyPair.pubKey, hashHex, sign.r, sign.s);
 
    console.log(verifyResult + "\n");
    if (verifyResult === false) throw Error("testSignatureVerify");
  }
}

function testAll()
{
testCurve167();
testCurve233();
testCurve307();
testCurve431();
performTestSignatureVerify("233");
performTestSignatureVerify("307");
performTestSignatureVerify("431");
}

module.exports = {testAll: testAll};