'use strict';
var gost89 = require('./gost89.js');

var WRAP_IV = new Buffer([
    0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05
]);

var key_wrap = function (cek, kek, iv) {
    var idx;
    var gost = gost89.init();
    var icv = new global.Uint8Array(4),
        cekicv = new global.Uint8Array(40),
        temp1 = new global.Uint8Array(40),
        temp2 = new global.Uint8Array(44),
        temp3 = new global.Uint8Array(48),
        result = new global.Uint8Array(48);

    gost.key(kek);
    gost.mac(32, cek, icv);

    for (idx=0; idx < 32; idx++) {
        cekicv[idx] = cek[idx];
    }
    for (idx=32; idx < 40; idx++) {
        cekicv[idx] = icv[idx - 32] || 0;
    }

    gost.crypt_cfb(iv, cekicv, temp1);

    for (idx=0; idx < 8; idx++) {
        temp2[idx] = iv[idx];
    }
    for (idx=8; idx < 44; idx++) {
        temp2[idx] = temp1[idx - 8];
    }

    for(idx=0; idx < 48; idx++) {
        temp3[idx] = temp2[44 - idx - 1];
    }

    gost.crypt_cfb(WRAP_IV, temp3, result);

    return new Buffer(result.slice(0, 44));
};

var key_unwrap = function (wcek, kek) {
    var idx, err;
    var gost = gost89.init();

    var icv = new global.Uint8Array(4),
        iv = new global.Uint8Array(8),
        cekicv = new global.Uint8Array(40),
        temp1 = new global.Uint8Array(40),
        temp2 = new global.Uint8Array(44),
        temp3 = new global.Uint8Array(48),
        icv_check = new global.Uint8Array(4);

    gost.key(kek);
    gost.decrypt_cfb(WRAP_IV, wcek, temp3);

    for(idx=0; idx < 44; idx++) {
        temp2[idx] = temp3[44 - idx - 1];
    }

    for (idx = 0; idx < 8; idx++ ) {
        iv[idx] = temp2[idx];
    }
    for (idx = 0; idx < 36; idx++) {
        temp1[idx] = temp2[idx + 8];
    }

    gost.decrypt_cfb(iv, temp1, cekicv);

    for (idx = 0; idx < 4; idx++) {
        icv[idx] = cekicv[idx + 32];
    }

    gost.mac(32, cekicv.slice(0, 32), icv_check);

    err = icv[0] ^ icv_check[0];
    err |= icv[1] ^ icv_check[1];
    err |= icv[2] ^ icv_check[2];
    err |= icv[3] ^ icv_check[3];

    if (err !== 0) {
        throw new Error("Key unwrap failed. Checksum mismatch");
    }

    return new Buffer(cekicv.slice(0, 32));
};

module.exports = {
    unwrap: key_unwrap,
    wrap: key_wrap,
};
