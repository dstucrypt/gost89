'use strict';

var Buffer = require('buffer').Buffer;
var Dstu = require('./dstu.js');

var Subst = function (data, mem) {
    this.k8 = mem.subarray(0, 16);
    this.k7 = mem.subarray(16, 32);
    this.k6 = mem.subarray(32, 48);
    this.k5 = mem.subarray(48, 64);
    this.k4 = mem.subarray(64, 80);
    this.k3 = mem.subarray(80, 96);
    this.k2 = mem.subarray(96, 112);
    this.k1 = mem.subarray(112, 128);

    var idx;

    for (idx = 0; idx < mem.length; idx++) {
        mem[idx] = data[idx];
    }
};

var Gost = function (sbox) {
    var mem = new global.Uint32Array(1162);

    this.k = mem.subarray(0, 8);
    this.k87 = mem.subarray(8, 264);
    this.k65 = mem.subarray(264, 520);
    this.k43 = mem.subarray(520, 776);
    this.k21 = mem.subarray(776, 1032);

    if (! (sbox instanceof Subst)) {
        sbox = new Subst(sbox, mem.subarray(1032, 1160));
    }
    this.n = mem.subarray(1160, 1162);


    this.boxinit(sbox);
};

Gost.prototype.boxinit = function (sbox) {
    var i;

    for (i = 0; i < 256; i++) {
        this.k87[i] = (sbox.k8[i>>>4] <<4 | sbox.k7 [i &15])<<24;
        this.k65[i] = (sbox.k6[i>>>4] << 4 | sbox.k5 [i &15])<<16;
        this.k43[i] = (sbox.k4[i>>>4] <<4  | sbox.k3 [i &15])<<8;
        this.k21[i] = sbox.k2[i>>>4] <<4  | sbox.k1 [i &15];
    }
};

Gost.prototype.pass = function (x) {
    x = this.k87[x>>>24 & 255] | this.k65[x>>>16 & 255]|
        this.k43[x>>> 8 & 255] | this.k21[x & 255];
    /* Rotate left 11 bits */
    return x<<11 | x>>>(32-11);
};

Gost.prototype.crypt64 = function (clear, out) {
    var n = this.n;
    n[0] = clear[0]|(clear[1]<<8)|(clear[2]<<16)|(clear[3]<<24);
    n[1] = clear[4]|(clear[5]<<8)|(clear[6]<<16)|(clear[7]<<24);
    /* Instead of swappclearg halves, swap names each round */

    n[1] ^= this.pass(n[0]+this.k[0]); n[0] ^= this.pass(n[1]+this.k[1]);
    n[1] ^= this.pass(n[0]+this.k[2]); n[0] ^= this.pass(n[1]+this.k[3]);
    n[1] ^= this.pass(n[0]+this.k[4]); n[0] ^= this.pass(n[1]+this.k[5]);
    n[1] ^= this.pass(n[0]+this.k[6]); n[0] ^= this.pass(n[1]+this.k[7]);

    n[1] ^= this.pass(n[0]+this.k[0]); n[0] ^= this.pass(n[1]+this.k[1]);
    n[1] ^= this.pass(n[0]+this.k[2]); n[0] ^= this.pass(n[1]+this.k[3]);
    n[1] ^= this.pass(n[0]+this.k[4]); n[0] ^= this.pass(n[1]+this.k[5]);
    n[1] ^= this.pass(n[0]+this.k[6]); n[0] ^= this.pass(n[1]+this.k[7]);

    n[1] ^= this.pass(n[0]+this.k[0]); n[0] ^= this.pass(n[1]+this.k[1]);
    n[1] ^= this.pass(n[0]+this.k[2]); n[0] ^= this.pass(n[1]+this.k[3]);
    n[1] ^= this.pass(n[0]+this.k[4]); n[0] ^= this.pass(n[1]+this.k[5]);
    n[1] ^= this.pass(n[0]+this.k[6]); n[0] ^= this.pass(n[1]+this.k[7]);

    n[1] ^= this.pass(n[0]+this.k[7]); n[0] ^= this.pass(n[1]+this.k[6]);
    n[1] ^= this.pass(n[0]+this.k[5]); n[0] ^= this.pass(n[1]+this.k[4]);
    n[1] ^= this.pass(n[0]+this.k[3]); n[0] ^= this.pass(n[1]+this.k[2]);
    n[1] ^= this.pass(n[0]+this.k[1]); n[0] ^= this.pass(n[1]+this.k[0]);

    out[0] = n[1]&0xff;  out[1] = (n[1]>>>8)&0xff;
    out[2] = (n[1]>>>16)&0xff; out[3]=n[1]>>>24;
    out[4] = n[0]&0xff;  out[5] = (n[0]>>>8)&0xff;
    out[6] = (n[0]>>>16)&0xff; out[7] = n[0]>>>24;
};

Gost.prototype.decrypt64 = function (crypt, out) {
    var n = this.n;
    n[0] = crypt[0]|(crypt[1]<<8)|(crypt[2]<<16)|(crypt[3]<<24);
    n[1] = crypt[4]|(crypt[5]<<8)|(crypt[6]<<16)|(crypt[7]<<24);

    n[1] ^= this.pass(n[0]+this.k[0]); n[0] ^= this.pass(n[1]+this.k[1]);
    n[1] ^= this.pass(n[0]+this.k[2]); n[0] ^= this.pass(n[1]+this.k[3]);
    n[1] ^= this.pass(n[0]+this.k[4]); n[0] ^= this.pass(n[1]+this.k[5]);
    n[1] ^= this.pass(n[0]+this.k[6]); n[0] ^= this.pass(n[1]+this.k[7]);

    n[1] ^= this.pass(n[0]+this.k[7]); n[0] ^= this.pass(n[1]+this.k[6]);
    n[1] ^= this.pass(n[0]+this.k[5]); n[0] ^= this.pass(n[1]+this.k[4]);
    n[1] ^= this.pass(n[0]+this.k[3]); n[0] ^= this.pass(n[1]+this.k[2]);
    n[1] ^= this.pass(n[0]+this.k[1]); n[0] ^= this.pass(n[1]+this.k[0]);

    n[1] ^= this.pass(n[0]+this.k[7]); n[0] ^= this.pass(n[1]+this.k[6]);
    n[1] ^= this.pass(n[0]+this.k[5]); n[0] ^= this.pass(n[1]+this.k[4]);
    n[1] ^= this.pass(n[0]+this.k[3]); n[0] ^= this.pass(n[1]+this.k[2]);
    n[1] ^= this.pass(n[0]+this.k[1]); n[0] ^= this.pass(n[1]+this.k[0]);

    n[1] ^= this.pass(n[0]+this.k[7]); n[0] ^= this.pass(n[1]+this.k[6]);
    n[1] ^= this.pass(n[0]+this.k[5]); n[0] ^= this.pass(n[1]+this.k[4]);
    n[1] ^= this.pass(n[0]+this.k[3]); n[0] ^= this.pass(n[1]+this.k[2]);
    n[1] ^= this.pass(n[0]+this.k[1]); n[0] ^= this.pass(n[1]+this.k[0]);

    out[0] = (n[1]&0xff);  out[1] = ((n[1]>>>8)&0xff);
    out[2] = ((n[1]>>>16)&0xff); out[3]=(n[1]>>>24);
    out[4] = (n[0]&0xff);  out[5] = ((n[0]>>>8)&0xff);
    out[6] = ((n[0]>>>16)&0xff); out[7] = (n[0]>>>24);
};

Gost.prototype.crypt64_cfb = function (iv, clear, out) {
    var j;
    var gamma = this.gamma;

    this.crypt64(iv, gamma);
    for (j = 0; j < 8; j++) {
        out[j] = clear[j] ^ gamma[j];
        iv[j] = out[j];
    }
};

Gost.prototype.decrypt64_cfb = function (iv, ctext, clear) {
    var j;
    var gamma = this.gamma;

    this.crypt64(iv, gamma);
    for (j = 0; j < 8; j++) {
        iv[j] = ctext[j];
        clear[j] = ctext[j] ^ gamma[j];
    }
};

Gost.prototype.crypt_cfb = function (iv, clear, out) {
    var blocks, idx, off;

    this.gamma = new global.Uint8Array(8);
    var cur_iv = new global.Uint8Array(8);
    for (idx=0; idx < 8; idx++) {
        cur_iv[idx] = iv[idx];
    }

    blocks = Math.ceil(clear.length  / 8);
    if (!blocks) {
        return;
    }

    if (!out) {
        out = Buffer.alloc(blocks * 8);
    }
    if (!Buffer.isBuffer(out)) {
        throw new Error("Either pass output buffer or nothing");
    }

    if (!Buffer.isBuffer(clear)) {
        clear = Buffer.from(clear, 'binary');
    }

    idx = 0;
    while (idx < blocks) {
        off = idx++ * 8;
        this.crypt64_cfb(cur_iv, clear.slice(off, off + 8), out.slice(off, off + 8));
    }
    if (out.length !== clear.length) {
        out = Buffer.from(out.slice(0, clear.length));
    }
    return out;
};

Gost.prototype.decrypt_cfb = function (iv, ctext, clear) {
    var blocks, idx, off;

    this.gamma = new global.Uint8Array(8);
    var cur_iv = new global.Uint8Array(8);
    for (idx=0; idx < 8; idx++) {
        cur_iv[idx] = iv[idx];
    }

    blocks = Math.ceil(ctext.length  / 8);
    if (!blocks) {
        return;
    }
    if (!clear) {
        clear = Buffer.alloc(blocks * 8);
    }
    if (!Buffer.isBuffer(clear)) {
        throw new Error("Either pass output buffer");
    }

    if (!Buffer.isBuffer(ctext)) {
        ctext = Buffer.from(ctext, 'binary');
    }

    idx = 0;
    while (idx < blocks) {
        off = idx++ * 8;
        this.decrypt64_cfb(cur_iv, ctext.slice(off, off + 8), clear.slice(off, off + 8));
    }
    if (clear.length !== ctext.length) {
        clear = Buffer.from(clear.slice(0, ctext.length));
    }
    return clear;
};

Gost.prototype.crypt = function (clear, out) {
    var blocks, off, idx;

    blocks = Math.ceil(clear.length  / 8);
    if (!blocks) {
        return;
    }

    if (!Buffer.isBuffer(clear)) {
        clear = Buffer.from(clear, 'binary');
    }
    if (!out) {
        out = Buffer.alloc(blocks * 8);
    }
    if (!Buffer.isBuffer(out)) {
        throw new Error("Either pass output buffer or nothing");
    }

    idx = 0;
    while (idx < blocks) {
        off = idx++ * 8;
        this.crypt64(clear.slice(off, off + 8), out.slice(off, off + 8));
    }

    if (out.length !== clear.length) {
        out = Buffer.from(out.slice(0, clear.length));
    }
    return out;

};

Gost.prototype.decrypt = function (cypher, clear) {
    var blocks, off;

    blocks = Math.ceil(cypher.length  / 8);
    if (!blocks) {
        return;
    }

    if (!Buffer.isBuffer(clear)) {
        clear = Buffer.alloc(blocks * 8);
    }
    if (!Buffer.isBuffer(cypher)) {
        cypher = Buffer.from(cypher, 'binary');
    }

    while (blocks--) {
        off = blocks * 8;
        this.decrypt64(cypher.slice(off, off + 8), clear.slice(off, off + 8));
    }

    if (clear.length !== cypher.length) {
        clear = Buffer.from(clear.slice(0, cypher.length));
    }
    return clear;
};

Gost.prototype.key = function (k) {
    var i, j;
    for(i=0,j=0; i<8; i++,j+=4)  {
        this.k[i] = k[j] | (k[j+1]<<8) | (k[j+2]<<16) | (k[j+3]<<24);
    }
};

Gost.prototype.mac = function (len, data, out) {
    var buf = new global.Uint8Array(8),
        buf2 = new global.Uint8Array(8);

    if (!Buffer.isBuffer(data)) {
        data = Buffer.from(data, 'binary');
    }

    var i;
    for (i=0;i+8 <= data.length; i+=8) {
        this.mac64(buf, data.slice(i, i+8));
    }

    if (i < data.length) {
        data = data.slice(i);
        for (i=0; i<data.length; i++) {
            buf2[i] = data[i];
        }
        this.mac64(buf, buf2);
    }

    if (i === 8) {
        for (i=0; i<buf2.length; i++) {
            buf2[i] = 0;
        }
        this.mac64(buf, buf2);
    }

    return this.mac_out(buf, len, out);
};

Gost.prototype.mac_out = function (buf, nbits, out) {
    var nbytes= nbits >>> 3;
    var rembits = nbits & 7;
    var mask =rembits?((1<rembits)-1):0;
    var i;
    if (!out) {
        out = Buffer.alloc(nbytes);
    }
    if (!Buffer.isBuffer(out)) {
        throw new Error("Either pass output buffer or nothing");
    }
    for (i=0;i<nbytes;i++) {
        out[i] = buf[i];
    }
    if (rembits) {
        out[i] = buf[i] & mask;
    }
    return out;

};

Gost.prototype.mac64 = function (buffer, block) {
    var n = this.n;
    var i;
    for (i=0; i<8; i++)
    {
        buffer[i]^=block[i];
    }
    n[0] = buffer[0]|(buffer[1]<<8)|(buffer[2]<<16)|(buffer[3]<<24);
    n[1] = buffer[4]|(buffer[5]<<8)|(buffer[6]<<16)|(buffer[7]<<24);
    /* Instead of swapping halves, swap names each round */

    n[1] ^= this.pass(n[0]+this.k[0]); n[0] ^= this.pass(n[1]+this.k[1]);
    n[1] ^= this.pass(n[0]+this.k[2]); n[0] ^= this.pass(n[1]+this.k[3]);
    n[1] ^= this.pass(n[0]+this.k[4]); n[0] ^= this.pass(n[1]+this.k[5]);
    n[1] ^= this.pass(n[0]+this.k[6]); n[0] ^= this.pass(n[1]+this.k[7]);

    n[1] ^= this.pass(n[0]+this.k[0]); n[0] ^= this.pass(n[1]+this.k[1]);
    n[1] ^= this.pass(n[0]+this.k[2]); n[0] ^= this.pass(n[1]+this.k[3]);
    n[1] ^= this.pass(n[0]+this.k[4]); n[0] ^= this.pass(n[1]+this.k[5]);
    n[1] ^= this.pass(n[0]+this.k[6]); n[0] ^= this.pass(n[1]+this.k[7]);

    buffer[0] = n[0] & 0xff;  buffer[1] = (n[0] >>> 8) &0xff;
    buffer[2] = (n[0] >>> 16) &0xff; buffer[3] = n[0] >>> 24;
    buffer[4] = n[1] & 0xff;  buffer[5] = (n[1] >>> 8) & 0xff;
    buffer[6] = (n[1] >>> 16) & 0xff; buffer[7] = n[1] >>> 24;
};

module.exports = Gost;
module.exports.Subst = Subst;
module.exports.init = function (sbox) {
    if (sbox === undefined) {
        sbox = Dstu.defaultSbox;
    }
    return new Gost(sbox);
};
