'use strict';

var Gost = require('./lib/gost89.js');
var Dstu = require('./lib/dstu.js');

var gost_init = function (sbox) {
    if (sbox === undefined) {
        sbox = Dstu.defaultSbox;
    }
    return new Gost(sbox);
};

module.exports = {
    init: gost_init,
};
