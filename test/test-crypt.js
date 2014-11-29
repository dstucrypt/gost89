var assert = require("assert"),
    gost89 = require("..");

describe('Gost', function() {
    describe('#crypt()', function() {
        it('should encrypt multiply blocks', function() {
            var expect_cypher = 'e393a17df2b6de6f2086d8230c277432';

            var ctx = gost89.init();
            var key = new Buffer('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', 'hex');
            var clear = new Buffer('0001020304050607f1f2f3f4f5f6f7f8', 'hex');
            var out = new Buffer(16);

            ctx.key(key);
            ctx.crypt(clear, out);

            assert.equal(expect_cypher, out.toString('hex'));
        });
    });

    describe('#decrypt()', function() {
        it('should decrypt multiply blocks', function() {
            var expect_clear = '0001020304050607f1f2f3f4f5f6f7f8';

            var ctx = gost89.init();
            var key = new Buffer('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', 'hex');
            var cypher = new Buffer('e393a17df2b6de6f2086d8230c277432', 'hex');
            var out = new Buffer(16);

            ctx.key(key);
            ctx.decrypt(cypher, out);

            assert.equal(expect_clear, out.toString('hex'));
        });
    });

    describe('#crypt_cfb()', function () {
        it('should encrypt multiply blocks in CFB mode', function () {
            var expect_c = '2087da2008227235a919d76142e8ce65';

            var ctx = gost89.init();
            var iv = new Buffer('F1F2F3F4F5F6F7F8', 'hex');
            var key = new Buffer('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', 'hex');
            var clear = new Buffer('0001020304050607f1f2f3f4f5f6f7f8', 'hex');
            var out = new Buffer(16);

            ctx.key(key);
            ctx.crypt_cfb(iv, clear, out);

            assert.equal(expect_c, out.toString('hex'));

        });
    });
});
