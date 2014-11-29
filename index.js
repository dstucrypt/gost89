'use strict';

var Gost = require('./lib/gost89.js');
var Dstu = require('./lib/dstu.js');
var Hash = require('./lib/hash.js');

module.exports = {
    init: Gost.init,
    Hash: Hash,
    gosthash: Hash.gosthash,
};
