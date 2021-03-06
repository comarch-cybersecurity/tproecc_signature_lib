/*jslint node: true */

'use strict';

var UA_ECC_LIB = require('jkurwa');
var UA_CURVES = require('./dstu4145_curves');

function DSTU4145Exception(sMessage) {
  this.name = "DSTU4145Exception";
  this.message = sMessage;
  this.stack = (new Error()).stack;
}
DSTU4145Exception.prototype = Object.create(Error.prototype);
DSTU4145Exception.prototype.constructor = DSTU4145Exception;

function DSTU4145(curve_type) {
  this.curve = DSTU4145._getCurve(curve_type);

  // Curve rand - hack to properly implement random
  this._enableNormalRand();
}


DSTU4145.prototype._enableNormalRand = function () {
  UA_ECC_LIB.Curve.prototype.rand = function () {
    var bits, words, ret, rand8;
    var getRandomValues = require('get-random-values');
    while (true) {
      bits = this.order.bitLength();
      words = Math.ceil(bits / 8);
      rand8 = new global.Uint8Array(words);
      rand8 = getRandomValues(rand8);
      ret = new UA_ECC_LIB.Field(rand8, 'buf8', this);

      if (!this.order.less(ret)) {
        return ret;
      }
    }
  };
};

DSTU4145.prototype._compareFieldNumbers = function (fieldNum1, fieldNum2) {
  var b1 = fieldNum1.bytes;
  var b2 = fieldNum2.bytes;

  if (fieldNum1.length !== fieldNum2.length) {
    throw new Error("field numbers different lens");
  }

  for (var index = fieldNum1.length - 1; index >= 0; index--) {
    var diff = Math.sign(b1[index] - b2[index]);
    if (diff !== 0) {
      return diff;
    }
  }
  return 0;
};

DSTU4145.prototype._enableFixedRand = function (randHex) {
  var ret = new UA_ECC_LIB.Field(randHex, 'hex', this.curve);

  var curveBits = this.curve.m;
  var xbit = ret.bitLength();

  if (xbit >= curveBits - 1) {
    throw new Error("provided fixed random (E param) must be lower that curve order");
  }

  UA_ECC_LIB.Curve.prototype.rand = function () {
    return ret;
  };
};

DSTU4145._getCurve = function (curve_name) {
  var curve_def = UA_CURVES[curve_name];
  if (curve_def === undefined) {
    throw new Error("Curve with such name was not defined");
  }
  var curve = new UA_ECC_LIB.Curve(curve_def);
  return curve;
};

DSTU4145.prototype.decodePublicKeyXY = function (xHex, yHex) {
  var pubX = new UA_ECC_LIB.Field(xHex, 'hex', this.curve);
  var pubY = new UA_ECC_LIB.Field(yHex, 'hex', this.curve);

  var pubKey = new UA_ECC_LIB.Pub(this.curve, this.curve.point(pubX, pubY), false);
  if (!pubKey.validate()) {
    throw new DSTU4145Exception("invalid public key parameters");
  }
  return pubKey;
};

DSTU4145.prototype.encodePublicKey = function (pubKey) {
  if (pubKey.type !== "Pub") {
    throw new Error("public key object expected");
  }
  var xHex = new Buffer(pubKey.x.truncate_buf8()).toString('hex');
  var yHex = new Buffer(pubKey.y.truncate_buf8()).toString('hex');
  return "04" + xHex + yHex;
};

DSTU4145.prototype.encodePrivateKey = function (privKey) {
  if (privKey.type !== "Priv") {
    throw new Error("private key object expected");
  }
  return new Buffer(privKey.d.truncate_buf8()).toString('hex');
};

DSTU4145.prototype._checkPrivateKey = function (privFieldNumber) {
  if (privFieldNumber.length > this.curve.order.length) {
    return false;
  }
  var result = this._compareFieldNumbers(this.curve.order, privFieldNumber);
  if (result <= 0) {
    return false;
  }
  return true;
};

DSTU4145.prototype.generateKeyPair = function (privScalarHex) {
  var privKeyCheck = false;
  var privFieldNumber;
  if (typeof privScalarHex === 'undefined') {
    privFieldNumber = this.curve.keygen().d;
    do {
      privKeyCheck = this._checkPrivateKey(privFieldNumber);
      privFieldNumber = privFieldNumber.shiftRight(1);
    } while (!privKeyCheck);
  } else {
    // check private key size
    privFieldNumber = new UA_ECC_LIB.Field(privScalarHex, 'hex', this.curve);
    if (!this._checkPrivateKey(privFieldNumber)) {
      throw new Error("private key > curve.order");
    }
  }

  var privKey = new UA_ECC_LIB.Priv(this.curve, privFieldNumber);
  var pubKey = privKey.pub();
  return {
    privKey: privKey,
    pubKey: pubKey
  };
};

DSTU4145._reverseBuffer = function (buffer) {
  var arr = [];
  var len = buffer.length;
  var index;

  for (index = 0; index < len; index += 1) {
    arr[index] = buffer[len - index - 1];
  }
  return new Buffer(arr);
};

DSTU4145.prototype.getKeyBytes = function () {
  return Math.floor((this.curve.m + 7) / 8);
};

DSTU4145.prototype._convertASNSignatureParam = function (signParam) {
  // add leading zeros

  var expectedLen = (this.curve.m + 7) / 8;
  if (signParam.length > expectedLen) {
    throw new Error("invalid signature parameter size");
  }

  var buf = Buffer.alloc(expectedLen);
  signParam.copy(buf, expectedLen - signParam.length, 0, signParam.length);

  var hexParam = buf.toString("hex");
  if ((buf[0] & 0x80) === 0x80) {
    hexParam = "00" + hexParam; // add one byte prefix for negative number 
  }
  return "02" + this.addASNLenPrefix(hexParam);
};

DSTU4145._addzero = function (u8) {
  var ret = [],
    i;
  for (i = 0; i < u8.length; i++) {
    ret.push(u8[i]);
  }
  ret.push(0);
  ret = ret.reverse();
  return ret;
};

DSTU4145.prototype._convertHash = function (hashHex) {
  if (! /^([0-9A-Fa-f][0-9A-Fa-f])+$/.test(hashHex))
    throw new DSTU4145Exception("hash is not a hex string");

  var hash = new Buffer(hashHex, "hex");
  hash = new UA_ECC_LIB.Field(DSTU4145._addzero(hash), 'buf8', this.curve);
  var curveBits = this.curve.m;
  var xbit = hash.bitLength();

  while (curveBits < xbit) { // end if xbit == 167
    hash = hash.clearBit(xbit - 1);
    xbit = hash.bitLength();
  }
  return DSTU4145._reverseBuffer(hash.buf8());
};

DSTU4145.prototype.encodeSignature = function (rHex, sHex) {
  var r = new Buffer(rHex, 'hex');
  var s = new Buffer(sHex, 'hex');
  return "30" + this.addASNLenPrefix(this.convertASNSignatureParam(r) + this.convertASNSignatureParam(s));
};

DSTU4145.prototype.fixedSign = function (privKey, hashHex, randHex) {
  this._enableFixedRand(randHex);
  // reverse hash - assuming hash test vector is already reversed as in formal Ukrainian test vectors
  var reversedHash = DSTU4145._reverseBuffer(new Buffer(hashHex, 'hex'));
  var res = this.sign(privKey, reversedHash.toString('hex'));
  this._enableNormalRand();
  return res;
};

DSTU4145.prototype.sign = function (privKey, hashHex) {
  if (privKey.type !== "Priv") {
    throw new Error("private key object expected");
  }
  var res = privKey.sign(this._convertHash(hashHex));
  var s = new Buffer(res.s.truncate_buf8()).toString('hex');
  var r = new Buffer(res.r.truncate_buf8()).toString('hex');
  return {
    r: r,
    s: s
  };
};

DSTU4145.prototype.verifyHexSignRS = function (pubKey, hashHex, signatureRHex, signatureSHex) {
  if (pubKey.type !== "Pub") {
    throw new Error("verifySign - public key object expected");
  }
  var signature = {
    r: new Buffer(signatureRHex, "hex"),
    s: new Buffer(signatureSHex, "hex")
  };

  return pubKey.verify(new Buffer(hashHex, "hex"), signature);
};

module.exports = DSTU4145;