'use strict';

var Gost = require('./lib/gost89.js');
var Dstu = require('./lib/dstu.js');
var Hash = require('./lib/hash.js');
var PRNG = require('./lib/prng.js');

var util = require('./lib/util.js');
var keywrap = require('./lib/keywrap.js');
var compat = require('./lib/compat.js');

module.exports = {
    init: Gost.init,
    PRNG: PRNG,
    Hash: Hash,
    gosthash: Hash.gosthash,
    dumb_kdf: util.dumb_kdf,
    pbkdf: util.pbkdf,
    wrap_key: keywrap.wrap,
    unwrap_key: keywrap.unwrap,
    compat: compat,
};
