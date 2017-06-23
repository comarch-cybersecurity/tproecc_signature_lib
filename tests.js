var dstu4145test = require('./dstu4145ECC/dstu4145_test');


var dstu4145_lib = require('./dstu4145ECC/dstu4145');

var asn1_lib = require('./asn1EncDec/asn1encdec');

function performTestDecodeSignature(dstuObj, encodedSignature, expectedR, expectedS) {
  var signature = asn1_lib.decodeSignature(dstuObj.getKeyBytes(), encodedSignature);
  var signR = signature.r.toString('hex');
  var signS = signature.s.toString('hex');
  console.log("signature:\n" + encodedSignature + "\n");
  console.log("r:" + signR);
  console.log("s:" + signS);
  if (expectedR !== signR || expectedS !== signS) throw new Error("testDecodeSignature");
  console.log("OK\n");
}

function testDecodeSignature233() {
  console.log("Test Decode Signature curve 233");
  var encodedSignature_233 = "3040021e0081c940172b9bbd25e5796d7f2d4fc3a45bba5cb96d6eabdec1ada7791d021e0055aee0b9da700155bbb277436147744f0b8c59fd8ae8f016a586d3c6b0";
  var expectedR_233 = "0081c940172b9bbd25e5796d7f2d4fc3a45bba5cb96d6eabdec1ada7791d";
  var expectedS_233 = "0055aee0b9da700155bbb277436147744f0b8c59fd8ae8f016a586d3c6b0";
  var dstuObj = new dstu4145_lib("DSTU4145_233");
  performTestDecodeSignature(dstuObj, encodedSignature_233, expectedR_233, expectedS_233);
}

function testDecodeSignature307() {
  console.log("Test Decode Signature curve 307");
  var encodedSignature_307 =
    "3052022701e9bc44dee592644b8775c9aeb46817a3cd1aab7581d7c0d7c8c79bc424bb9bc6608c18d423e7022700f1486ac0023e0dd572fa8aec8935381632845625179182db9952ea3294bb42db2179e436a776";
  var expectedR_307 = "01e9bc44dee592644b8775c9aeb46817a3cd1aab7581d7c0d7c8c79bc424bb9bc6608c18d423e7";
  var expectedS_307 = "00f1486ac0023e0dd572fa8aec8935381632845625179182db9952ea3294bb42db2179e436a776";

  var dstuObj = new dstu4145_lib("DSTU4145_307");
  performTestDecodeSignature(dstuObj, encodedSignature_307, expectedR_307, expectedS_307);
}

function testDecodeSignature431() {
  console.log("Test Decode Signature curve 431");
  var encodedSignature_431 = "3070023605f081b2a3525d13b0cc73ef3545c62c3e717abd38074cce93d9b1927ff5333eaca1c17b63ccec7aa30d403f0f277f38b48860d233a602361277d06d5510b139f8358adb12cbff45798688719adc89c761b0f6e3c1e4b38d5867c13ea35cb18f0cd2256083757a714c191e2c2ffe";
  var expectedR_431 = "05f081b2a3525d13b0cc73ef3545c62c3e717abd38074cce93d9b1927ff5333eaca1c17b63ccec7aa30d403f0f277f38b48860d233a6";
  var expectedS_431 = "1277d06d5510b139f8358adb12cbff45798688719adc89c761b0f6e3c1e4b38d5867c13ea35cb18f0cd2256083757a714c191e2c2ffe";
  var dstuObj = new dstu4145_lib("DSTU4145_431");
  performTestDecodeSignature(dstuObj, encodedSignature_431, expectedR_431, expectedS_431);
}

testDecodeSignature233();
testDecodeSignature307();
testDecodeSignature431();


try {
    dstu4145test.testAll();
}
catch (e) {
    if (e.name == "DSTU4145Exception")
        console.log(e.name);
    else
        throw e;
}
