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
                salt = Buffer.from('31a58dc1462981189cf6c701e276c7553a5ab5f6e36d8418e4aa40c930cf3876','hex');

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

    describe('key_wrap()', function () {
        it('should wrap encryption key', function () {
            var kek = Buffer.from('9c6e6852023b46f499f25b9b0eb7027387fdd5650f5d638ee5f99eb8dc781fde', 'hex'),
                cek = Buffer.from('11080811020a0d0913040f020111190b04060c101d1c0a0911060e160b121419', 'hex'),
                iv = Buffer.from('09100509181c0515', 'hex');

            var expect_key = 'e90fe95628e715f4d6f3d1151ded367250f7006648ffffde574a4ea38250c1c5a0fdff11f36d9186d3b27c60';

            var key = gost89.wrap_key(cek, kek, iv);
            assert.equal(key.toString('hex'), expect_key);
        });
    });

    describe('key_unwrap()', function () {
        it('should unwrap encryption key', function () {
            var wcek = Buffer.from('e90fe95628e715f4d6f3d1151ded367250f7006648ffffde574a4ea38250c1c5a0fdff11f36d9186d3b27c60', 'hex');
            var kek = Buffer.from('9c6e6852023b46f499f25b9b0eb7027387fdd5650f5d638ee5f99eb8dc781fde', 'hex');

            var expect_key = '11080811020a0d0913040f020111190b04060c101d1c0a0911060e160b121419';

            var key = gost89.unwrap_key(wcek, kek);
            assert.equal(key.toString('hex'), expect_key);

            expect_key = '11080811020a0d0913040f020111190b04060c101d1c0a0911060e160b121419';
            wcek = Buffer.from('359a37cf972520b590ef109b7c454c991d95da782e30ac9fe917fbb52e9402a4d236fd030f49627ec63c2684', 'hex'),
            kek = Buffer.from('1de57ae661b7e142727170dd5066d04bd63231d5a207778075d17a831e853902', 'hex');
            key = gost89.unwrap_key(wcek, kek);
            assert.equal(key.toString('hex'), expect_key);

        });

    });

});
