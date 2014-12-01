'use strict';
var keywrap = require('./keywrap.js'),
    util = require('./util.js'),
    Gost = require('./gost89.js'),
    Hash = require('./hash.js');

var convert_password = function (parsed, pw) {
    if (parsed.format === 'IIT') {
        return util.dumb_kdf(pw, 10000);
    }
    if (parsed.format === 'PBES2') {
        return util.pbkdf(pw, parsed.salt, parsed.iters);
    }

    throw new Error("Failed to convert key");
};

var decode_data = function (parsed, pw) {
    var bkey;

    var ctx = Gost.init();
    var buf, obuf;
    bkey = convert_password(parsed, pw, true);
    ctx.key(bkey);

    if (parsed.format === 'IIT') {
        buf = new Buffer.concat([parsed.body, parsed.pad]);
        obuf = new Buffer(buf.length);
        ctx.decrypt(buf, obuf);
        return obuf.slice(0, parsed.body.length);
    }
    if (parsed.format === 'PBES2') {
        buf = parsed.body;
        obuf = new Buffer(buf.length);
        ctx.decrypt_cfb(parsed.iv, buf, obuf);
        return obuf;
    }
};

var compute_hash = function (contents) {
    return Hash.gosthash(contents);
};

var gost_unwrap = function (kek, inp) {
    return keywrap.unwrap(inp, kek);
};

var gost_keywrap = function (kek, inp, iv) {
    return keywrap.wrap(inp, kek, iv);
};

var gost_kdf = function (buffer) {
    return compute_hash(buffer);
};

var gost_crypt = function (mode, inp, key, iv) {
    var ctx = Gost.init();
    ctx.key(key);
    if (mode) {
        return ctx.decrypt_cfb(iv, inp);
    } else {
        return ctx.crypt_cfb(iv, inp);
    }
};

var gost_decrypt_cfb = function(cypher, key, iv) {
    return gost_crypt(1, cypher, key, iv);
};

var gost_encrypt_cfb = function(cypher, key, iv) {
    return gost_crypt(0, cypher, key, iv);
};

module.exports.decode_data = decode_data;
module.exports.convert_password = convert_password;
module.exports.compute_hash = compute_hash;
module.exports.gost_kdf = gost_kdf;
module.exports.gost_unwrap = gost_unwrap;
module.exports.gost_keywrap = gost_keywrap;
module.exports.gost_decrypt_cfb = gost_decrypt_cfb;
module.exports.gost_encrypt_cfb = gost_encrypt_cfb;
module.exports.algos = function () {
    return {
        kdf: gost_kdf,
        keywrap: gost_keywrap,
        keyunwrap: gost_unwrap,
        encrypt: gost_encrypt_cfb,
        decrypt: gost_decrypt_cfb,
        hash: compute_hash,
        storeload: decode_data,
    };
};
