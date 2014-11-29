var assert = require("assert"),
    gost89 = require("..");

describe('Hash', function() {
    describe('#gosthash()', function() {
        it('should hash padded value', function() {
            var input = '12345678901234567890123456789011';
            var expect_ret = '7686f3f4b113aadc97bca9ea054f41821f0676c5c28ffb987e41797a568e1ed4';
            var ret = gost89.gosthash(input);
            assert.equal(ret.toString('hex'), expect_ret);

            input = new Buffer([
                0,  1,  2,  3,  4,  5,  6,  7,
                8,  9, 10, 11, 12, 13, 14, 15,
                16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31
            ]);
            expect_ret = '811cb06a8ee423182d9cc9d281f783908f4cfbaf47a68be8415d3499674a3063';

            ret = gost89.gosthash(input);
            assert.equal(ret.toString('hex'), expect_ret);
        });
    });
});
