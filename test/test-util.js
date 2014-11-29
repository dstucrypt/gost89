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
});
