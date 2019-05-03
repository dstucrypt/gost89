'use strict';

var Buffer = require('buffer').Buffer;
var Gost = require('./gost89');

var PRNG = function (key) {
    var ctx = Gost.init();
    var counter = new global.Uint8Array([0, 0, 0, 0, 0, 0, 0, 0]);
    var I = new global.Uint8Array(8),
        X = new global.Uint8Array(8);
    ctx.key(key);

    var increment = function() {
        var idx, zero = 0, len = 8;
        for (idx = 0; idx < len; idx++) {
            counter[idx] ++;
            if (counter[idx] > 0) {
                break;
            } 
                
            zero = idx - 1;
        }
        for (idx = 0; idx < zero; idx++) {
            counter[idx] = 0;
        }
    };

    var bit = function() {
        var idx, ret;
        ctx.crypt64(counter, I);
        for (idx = 0; idx < 8; idx++) {
            I[idx] ^= counter[idx];
        }
        ctx.crypt64(I, X);
        ret = Buffer.from(X);

        for (idx = 0; idx < 8; idx++) {
            X[idx] ^= I[idx];
        }
        ctx.crypt64(X, counter);

        increment(counter);
        return ret;
    };

    var value = function () {
        var ret = Buffer.alloc(8);
        var idx, bidx;
        var step;

        for (idx=0; idx < 8; idx++) {
            for (bidx=0; bidx < 8; bidx++) {
                step = bit();
                ret[idx] |= (step[0] & 1) << bidx;
            }
        }

        return ret;
    };

    return {
        next: function(bytes) {
            var off = 0;
            var rb = Buffer.alloc(bytes);
            var step;
            while (bytes > off) {
                step = value();
                step.copy(rb, off);
                off += step.length;
            }
            return rb;
        }
    };
};

PRNG.seed = function (seed) {
    return new PRNG(seed);

};

module.exports = PRNG;
