var assert = require("assert"),
    gost89 = require("..");

describe('Gost', function() {
    describe('#crypt()', function() {
        it('should encrypt multiply blocks', function() {
            var expect_cypher = 'e393a17df2b6de6f2086d8230c277432';

            var ctx = gost89.init();
            var key = Buffer.from('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', 'hex');
            var clear = Buffer.from('0001020304050607f1f2f3f4f5f6f7f8', 'hex');
            var out = Buffer.alloc(16);

            ctx.key(key);
            ctx.crypt(clear, out);

            assert.equal(out.toString('hex'), expect_cypher);
        });
    });

    describe('#decrypt()', function() {
        it('should decrypt multiply blocks', function() {
            var expect_clear = '0001020304050607f1f2f3f4f5f6f7f8';

            var ctx = gost89.init();
            var key = Buffer.from('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', 'hex');
            var cypher = Buffer.from('e393a17df2b6de6f2086d8230c277432', 'hex');
            var out = Buffer.alloc(16);

            ctx.key(key);
            ctx.decrypt(cypher, out);

            assert.equal(out.toString('hex'), expect_clear);
        });
    });

    describe('#crypt_cfb()', function () {
        it('should encrypt multiply blocks in CFB mode', function () {
            var expect_c = '2087da2008227235a919d76142e8ce65';

            var ctx = gost89.init();
            var iv = Buffer.from('F1F2F3F4F5F6F7F8', 'hex');
            var key = Buffer.from('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', 'hex');
            var clear = Buffer.from('0001020304050607f1f2f3f4f5f6f7f8', 'hex');
            var out = Buffer.alloc(16);

            ctx.key(key);
            ctx.crypt_cfb(iv, clear, out);

            assert.equal(out.toString('hex'), expect_c);
        });
    });

    describe('#decrypt_cfb()', function () {
        it('should decrypt multiply blocks in CFB mode', function () {

            var expect_clear = '0001020304050607f1f2f3f4f5f6f7f8';

            var ctext = Buffer.from('2087da2008227235a919d76142e8ce65', 'hex');
            var clear = Buffer.alloc(16);
            var ctx = gost89.init();

            var iv = Buffer.from('F1F2F3F4F5F6F7F8', 'hex');
            var key = Buffer.from('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', 'hex');

            ctx.key(key);
            ctx.decrypt_cfb(iv, ctext, clear);

            assert.equal(clear.toString('hex'), expect_clear);

        });
    });
});
