'use strict';

var Hash = require('./Hash.js');

var dumb_kdf = function (input, n_passes) {
    var ctx = Hash.init();
    var hash = new global.Uint32Array(32);

    ctx.update(input);
    ctx.finish(hash);

    n_passes--;

    while(n_passes--) {
        ctx.reset();
        ctx.update32(hash);
        ctx.finish(hash);
    }

    return new Buffer(hash);
};

module.exports = {
    dumb_kdf: dumb_kdf,
};
