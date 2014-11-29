'use strict';
var gost89 = require('./gost89.js');

var swap_bytes = function (w, k)
{
    var i,j;
    for (i=0;i<4;i++) {
        for (j=0;j<8;j++) {
            k[i+4*j]=w[8*i+j];
        }
    }
};

var c8buf = new global.Uint8Array(8);
var circle_xor8 = function (w, k)
{
    var i;
    for (i=0; i<8; i++) {
        c8buf[i] = w[i];
    }
    for (i=0; i<24; i++) {
        k[i] = w[i + 8];
    }
    for(i=0;i<8;i++) {
        k[i+24]=c8buf[i]^k[i];
    }
};

var t16b = new global.Uint16Array(1);
var transform_3 = function (data)
{
    var i;
    t16b[0]=(data[0]^data[2]^data[4]^data[6]^data[24]^data[30])|
        ((data[1]^data[3]^data[5]^data[7]^data[25]^data[31])<<8);

    for (i=0; i<30; i++) {
        data[i] = data[i+2];
    }
    data[30] = t16b[0] &0xff;
    data[31] = t16b[0] >>> 8;
};

var ab2 = new global.Int32Array(4);
var add_blocks = function (n, left, right) {
    var i;
    for (i=0; i<n; i++) {
        ab2[0] = left[i];
        ab2[1] = right[i];
        ab2[2] = ab2[0] + ab2[1] + ab2[3];
        left[i] =  ab2[2] & 0xFF;
        ab2[3] =  ab2[2] >>> 8;
    }

    return ab2[3];
};

/* Xor two sequences of bytes */
var xor_blocks = function (ret, a, b)
{
    var i;
    var len = a.length;
    for (i=0;i<len;i++) {
        ret[i]=a[i]^b[i];
    }
};

var Hash = function () {
    this.gost = gost89.init();
    this.left = null;
    this.len = 0;
    this.H = new global.Uint8Array(32);
    this.S = new global.Uint8Array(32);
    this.buf = new global.Uint8Array(32);

    var hash_mem = new global.Uint8Array(160);

    this.U = hash_mem.slice(0, 32);
    this.W = hash_mem.slice(32, 64);
    this.V = hash_mem.slice(64, 96);
    this._S = hash_mem.slice(96, 128);
    this.Key = hash_mem.slice(128, 160);
    this.mem = hash_mem;

};

/*
 *     Calculate H(i+1) = Hash(Hi,Mi)
 *     Where H and M are 32 bytes long
 */
Hash.prototype.step = function(H, M)
{
    var U = this.U,
        W = this.W,
        V = this.V,
        S = this._S,
        Key = this.Key;

    var gost = this.gost;

    var i;
    /* Compute first key */
    xor_blocks(W,H,M,32);
    swap_bytes(W,Key);
    /* Encrypt first 8 bytes of H with first key*/
    gost.key(Key);
    gost.crypt64(H,S);
    /* Compute second key*/
    circle_xor8(H,U);
    circle_xor8(M,V);
    circle_xor8(V,V);
    xor_blocks(W,U,V,32);
    swap_bytes(W,Key);
    /* encrypt second 8 bytes of H with second key*/
    gost.key(Key);
    gost.crypt64(H.slice(8, 16), S.slice(8, 16));
    /* compute third key */
    circle_xor8(U,U);
    U[31]=~U[31]; U[29]=~U[29]; U[28]=~U[28]; U[24]=~U[24];
    U[23]=~U[23]; U[20]=~U[20]; U[18]=~U[18]; U[17]=~U[17];
    U[14]=~U[14]; U[12]=~U[12]; U[10]=~U[10]; U[ 8]=~U[ 8];
    U[ 7]=~U[ 7]; U[ 5]=~U[ 5]; U[ 3]=~U[ 3]; U[ 1]=~U[ 1];
    circle_xor8(V,V);
    circle_xor8(V,V);
    xor_blocks(W,U,V,32);
    swap_bytes(W,Key);
    /* encrypt third 8 bytes of H with third key*/
    gost.key(Key);
    gost.crypt64(H.slice(16, 24), S.slice(16, 24));
    /* Compute fourth key */
    circle_xor8(U,U);
    circle_xor8(V,V);
    circle_xor8(V,V);
    xor_blocks(W,U,V,32);
    swap_bytes(W,Key);
    /* Encrypt last 8 bytes with fourth key */
    gost.key(Key);
    gost.crypt64(H.slice(24, 32), S.slice(24, 32));
    for (i=0;i<12;i++)  {
        transform_3(S);
    }

    xor_blocks(S,S,M,32);
    transform_3(S);
    xor_blocks(S,S,H,32);

    for (i=0;i<61;i++)  {
        transform_3(S);
    }

    for (i=0; i< 32; i++) {
        H[i] = S[i];
    }

    return 1;
};


Hash.prototype.update = function (block) {
    if (typeof block === 'string') {
        block = new Buffer(block, 'binary');
    }
    if (this.left) {
        block = Buffer.concat([this.left, block]);
    }
    var block32 = block;
    var off = 0;
    while ((block.length - off) >= 32) {
        this.step(this.H, block32);
        add_blocks(32, this.S, block32);
        off += 32;
        block32 = block.slice(off, off + 32);
    }
    this.len += off;

    if (block32.length > 0) {
        this.left = new Buffer(block32);
        return;
    }
};

Hash.prototype.update32 = function (block32) {
    this.step(this.H, block32);
    add_blocks(32, this.S, block32);
    this.len += 32;
};

Hash.prototype.finish = function (hashval) {
    var buf = this.buf;
    var fin_len = this.len;
    var idx = 0;

    if (this.left) {
        for (idx=0; idx<this.left.length; idx++) {
            buf[idx] = this.left[idx];
        }
        this.step(this.H, buf);
        add_blocks(32, this.S, buf);
        fin_len += this.left.length;
        this.left = null;

        for (idx=0; idx < 32; idx++) {
            buf[idx] = 0;
        }
    }

    fin_len <<= 3;
    idx = 0;
    while (fin_len > 0) {
        buf[idx++] = fin_len & 0xFF;
        fin_len >>= 8;
    }

    this.step(this.H, buf);
    this.step(this.H, this.S);

    for (idx=0 ; idx < 32; idx++) {
        hashval[idx] = this.H[idx];
    }
    return hashval;
};

Hash.prototype.reset = function () {
    var idx;
    for (idx=0 ; idx < 32; idx++) {
        this.H[idx] = 0;
        this.S[idx] = 0;
    }
    this.left = null;
    this.len = 0;
};

var hash_init = function () {
    return new Hash();
};

Hash.init = hash_init;
Hash.gosthash = function (data, ret) {
    var ctx = hash_init();
    if (typeof data === 'string') {
        data = new Buffer(data, 'binary');
    }
    ctx.update(data);
    if (ret === undefined) {
        ret = new global.Uint8Array(32);
    }
    return new Buffer(ctx.finish(ret));
};
module.exports = Hash;
