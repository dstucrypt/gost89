Gost89
======

Gost89 cipher and hash function implementation in JS

[![Build Status](https://travis-ci.org/dstucrypt/gost89.svg?branch=master)](https://travis-ci.org/dstucrypt/gost89)
[![npm module](https://badge.fury.io/js/gost89.svg)](https://www.npmjs.org/package/gost89)
[![dependencies](https://david-dm.org/dstucrypt/gost89.png)](https://david-dm.org/dstucrypt/gost89)

Algos
-----

* DSTU Gost 34311-95 hash function
* DSTU Gost 28147-2009 CFB mode block cipher
* DSTU Gost 28147-2009 ECB mode block cipher
* DSTU Gost 28147 key wrapper as specified by DSTSZI [0]
* PBKDF (Gost-34311 based)
* Dumb KDF (N-iterations of hash)

[0] http://dstszi.kmu.gov.ua/dstszi/control/uk/publish/article?showHidden=1&art_id=90096&cat_id=38837

GOST-DSTU Notice
----------------

This package implements GOST functions, however S-BOX used by default comes
from Ukrainian counterpart standard DSTU as original GOST does not specify
explicitly what table to use.


Examples
--------

All function except Hash.update() accept buffer objects, string or byte arrays.

Hash messages:
```js
var gost89 = require("gost89");
var hash = gost89.gosthash("LA LA LA SHTIRLITZ KURWA VODKA MATRIOSKA");
// <Buffer 0a 32 7f 3b ce e1 f3 de 0f 40 61 2e c3 ce d0 a3 29 51 b8 b2 16 8e 9a 01 0f 5b 15 46 c0 a9 1d 93>

var hash_ctx = gost89.Hash.init();
hash_ctx.update("ARBITARY SIZED VODKA");
hash_ctx.update("VODKA VODKA MORE VODKA");
var hash = hash_ctx.finish(Buffer.alloc(32));
// <Buffer 2c 1e d1 f1 2c 05 13 38 b2 7f 42 5d ea df e0 62 17 e6 9b 2c 19 d4 4a cd 24 ac 8d 5b b7 53 34 3f>

hash_ctx.reset();
hash.update32(buffer_of_32_bytes);
var hash = hash_ctx.finish(Buffer.alloc(32));
```


Encrypt message:

```js
var gost = gost89.init();
var clear = Buffer.from('lol', 'binary');
gost.key(Buffer.alloc(32));
var out = gost.crypt(clear, out);
```

Encrypt messages in CFB mode:

```js
var gost = gost89.init();
var out = gost.crypt_cfb(iv, clear);
// out contains encrypted text
```


Properly encrypt message:

```js
var gost = gost89.init();
var key = crypto.randomBytes(32);
gost.key(key);
var enc = gost.crypt(text, enc);

var iv = crypto.randomBytes(8);
var shared_key = some_diffie_hellman_here(me, you); // see jkurwa
var wrapped_key = gost89.wrap_key(key, shared_key, iv);
// send enc and wrapped_key to other party
```
