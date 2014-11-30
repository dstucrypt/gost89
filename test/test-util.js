var assert = require("assert"),
    gost89 = require("..");

describe('utils', function () {
    describe('dumb_kdf()', function () {
        it('should expand password into key', function () {
            var input = '123123';
            var expect_key = '3709d09a3574045a52ee9ac65d6277282e065abc597ab0330bd275446230b6a6';

            var key = gost89.dumb_kdf(input, 10000);
            assert.equal(key.toString('hex'), expect_key);

        });
    });

    describe('pbkdf()', function () {
        it('should expand password into key', function () {
            var input = 'password',
                salt = new Buffer('31a58dc1462981189cf6c701e276c7553a5ab5f6e36d8418e4aa40c930cf3876','hex');

            var expect_key10000 = 'c4e7f788e60c731a2cfedd300af67bd2ee9458532a793e5280ae7f8c1e562e44',
                expect_key1 = 'b1d0fba9e976971b3f0eb3db1d574f972a862d68f67eadaa7ca9161b76f368da',
                expect_key2 = '4616a2cbfd39ab3e10ca60dbe194b311226461a964d69a536262924642c776ea';

            var key = gost89.pbkdf(input, salt, 1);
            assert.equal(key.toString('hex'), expect_key1);
            key = gost89.pbkdf(input, salt, 2);
            assert.equal(key.toString('hex'), expect_key2);
            key = gost89.pbkdf(input, salt, 10000);
            assert.equal(key.toString('hex'), expect_key10000);

        });
    });
});
