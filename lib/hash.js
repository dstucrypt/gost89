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

/*
 *     Calculate H(i+1) = Hash(Hi,Mi)
 *     Where H and M are 32 bytes long
 */
var hash_mem = global.Uint8Array(160);
var hash_step = function(gost, H, M)
{
    var U = hash_mem.slice(0, 32);
    var W = hash_mem.slice(32, 64);
    var V = hash_mem.slice(64, 96);
    var S = hash_mem.slice(96, 128);
    var Key = hash_mem.slice(128, 160);
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

var hash_block = function (ctx, block) {
    hash_step(ctx.gost, ctx.H, block);
    add_blocks(32, ctx.S, block);
};

var finish_hash = function (ctx, hashval) {
    var buf = new global.Uint8Array(32);
    var fin_len = 32;
    fin_len <<= 3;
    var idx = 0;

    var H = new global.Uint8Array(32);
    var S = new global.Uint8Array(32);
    for (idx=0; idx<32; idx++) {
        H[idx] = ctx.H[idx];
        S[idx] = ctx.S[idx];
    }

    idx = 0;
    while (fin_len > 0) {
        buf[idx++] = fin_len & 0xFF;
        fin_len >>= 8;
    }

    hash_step(ctx.gost, H, buf);

    hash_step(ctx.gost, H, S);

    for (idx=0 ; idx < 32; idx++) {
        hashval[idx] = H[idx];
    }
};

var Hash = function () {
    this.gost = gost89.init();
    this.left = null;
    this.len = 0;
    this.H = new global.Uint8Array(32);
    this.S = new global.Uint8Array(32);
};

Hash.prototype.update = function (data) {
    return hash_block(this, data);
};

Hash.prototype.finish = function (ret) {
    if (ret === undefined) {
        ret = new global.Uint32Array(32);
    }

    finish_hash(this, ret);
    return ret;
};

var hash_init = function () {
    return new Hash();
};

Hash.init = hash_init;
Hash.gosthash = function (data) {
    var ctx = hash_init();
    if (typeof data === 'string') {
        data = new Buffer(data, 'binary');
    }
    hash_block(ctx, data);
    return new Buffer(ctx.finish());
};
module.exports = Hash;
