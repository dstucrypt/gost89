'use strict';

var Subst = function (data, mem) {
    this.k8 = mem.slice(0, 16);
    this.k7 = mem.slice(16, 32);
    this.k6 = mem.slice(32, 48);
    this.k5 = mem.slice(48, 64);
    this.k4 = mem.slice(64, 80);
    this.k3 = mem.slice(80, 96);
    this.k2 = mem.slice(96, 112);
    this.k1 = mem.slice(112, 128);

    var idx;

    for (idx = 0; idx < mem.length; idx++) {
        mem[idx] = data[idx];
    }
};

var Gost = function (sbox) {
    var mem = new global.Uint32Array(1162);

    this.k = mem.slice(0, 8);
    this.k87 = mem.slice(8, 264);
    this.k65 = mem.slice(264, 520);
    this.k43 = mem.slice(520, 776);
    this.k21 = mem.slice(776, 1032);

    if (! (sbox instanceof Subst)) {
        sbox = new Subst(sbox, mem.slice(1032, 1160));
    }
    this.n = mem.slice(1160, 1162);


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

Gost.prototype.crypt64_cfb = function (iv, clear, out) {
    var j;
    var gamma = this.gamma;

    this.crypt64(iv, gamma);
    for (j = 0; j < 8; j++) {
        iv[j] = out[j] = clear[j] ^ gamma[j];
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
    while (blocks--) {
        off = blocks * 8;
        this.crypt64_cfb(cur_iv, clear.slice(off, off + 8), out.slice(off, off + 8));
    }
};

Gost.prototype.crypt = function (clear, out) {
    var blocks, off;

    blocks = Math.ceil(clear.length  / 8);
    if (!blocks) {
        return;
    }
    while (blocks--) {
        off = blocks * 8;
        this.crypt64(clear.slice(off, off + 8), out.slice(off, off + 8));
    }
};

Gost.prototype.key = function (k) {
    var i, j;
    for(i=0,j=0; i<8; i++,j+=4)  {
        this.k[i] = k[j] | (k[j+1]<<8) | (k[j+2]<<16) | (k[j+3]<<24);
    }
};

var gost_init = function (sbox) {
    return new Gost(sbox);
};

module.exports = {
    init: gost_init,
};
