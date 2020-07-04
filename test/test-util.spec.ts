import {dumb_kdf, pbkdf} from '../src/util';
import {unwrap_key, wrap_key} from '../src/keywrap';
import {Buffer} from '../src/types';

describe('utils', () => {
  describe('dumb_kdf()', () => {
    it('should expand password into key', () => {
      const input = Buffer.from('123123', 'binary');
      const expect_key =
        '3709d09a3574045a52ee9ac65d6277282e065abc597ab0330bd275446230b6a6';

      const key = dumb_kdf(input, 10000);
      expect(key.toString('hex')).toEqual(expect_key);
    });
  });

  describe('pbkdf()', () => {
    it('should expand password into key', () => {
      const input = Buffer.from('password', 'binary');
      const salt = Buffer.from(
        '31a58dc1462981189cf6c701e276c7553a5ab5f6e36d8418e4aa40c930cf3876',
        'hex'
      );

      const expect_key10000 =
        'c4e7f788e60c731a2cfedd300af67bd2ee9458532a793e5280ae7f8c1e562e44';
      const expect_key1 =
        'b1d0fba9e976971b3f0eb3db1d574f972a862d68f67eadaa7ca9161b76f368da';
      const expect_key2 =
        '4616a2cbfd39ab3e10ca60dbe194b311226461a964d69a536262924642c776ea';

      const key1 = pbkdf(input, salt, 1);
      expect(key1.toString('hex')).toEqual(expect_key1);
      const key2 = pbkdf(input, salt, 2);
      expect(key2.toString('hex')).toEqual(expect_key2);
      const key3 = pbkdf(input, salt, 10000);
      expect(key3.toString('hex')).toEqual(expect_key10000);
    });
  });

  describe('key_wrap()', () => {
    it('should wrap_key encryption key', () => {
      const kek = Buffer.from(
        '9c6e6852023b46f499f25b9b0eb7027387fdd5650f5d638ee5f99eb8dc781fde',
        'hex'
      );
      const cek = Buffer.from(
        '11080811020a0d0913040f020111190b04060c101d1c0a0911060e160b121419',
        'hex'
      );
      const iv = Buffer.from('09100509181c0515', 'hex');

      const expect_key =
        'e90fe95628e715f4d6f3d1151ded367250f7006648ffffde574a4ea38250c1c5a0fdff11f36d9186d3b27c60';

      const key = wrap_key(cek, kek, iv);
      expect(key.toString('hex')).toEqual(expect_key);
    });
  });

  describe('key_unwrap()', () => {
    it('should unwrap_key encryption key', () => {
      let wcek = Buffer.from(
        'e90fe95628e715f4d6f3d1151ded367250f7006648ffffde574a4ea38250c1c5a0fdff11f36d9186d3b27c60',
        'hex'
      );
      let kek = Buffer.from(
        '9c6e6852023b46f499f25b9b0eb7027387fdd5650f5d638ee5f99eb8dc781fde',
        'hex'
      );

      let expect_key =
        '11080811020a0d0913040f020111190b04060c101d1c0a0911060e160b121419';

      let key = unwrap_key(wcek, kek);
      expect(key.toString('hex')).toEqual(expect_key);

      expect_key =
        '11080811020a0d0913040f020111190b04060c101d1c0a0911060e160b121419';
      wcek = Buffer.from(
        '359a37cf972520b590ef109b7c454c991d95da782e30ac9fe917fbb52e9402a4d236fd030f49627ec63c2684',
        'hex'
      );
      kek = Buffer.from(
        '1de57ae661b7e142727170dd5066d04bd63231d5a207778075d17a831e853902',
        'hex'
      );
      key = unwrap_key(wcek, kek);
      expect(key.toString('hex')).toEqual(expect_key);
    });
  });
});
