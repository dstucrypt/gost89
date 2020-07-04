import {Gost} from './src/gost89';
import {gosthash, Hash} from './src/hash';
import {dumb_kdf, pbkdf} from './src/util';
import {unwrap_key, wrap_key} from './src/keywrap';
import {
  algos,
  compute_hash,
  convert_password,
  decode_data,
  gost_decrypt_cfb,
  gost_encrypt_cfb,
  gost_kdf,
  gost_keywrap,
  gost_unwrap,
} from './src/compat';
import {PRNG} from './src/prng';

export default {
  init: () => {
    return new Gost();
  },
  PRNG,
  Hash,
  gosthash,
  dumb_kdf,
  pbkdf,
  wrap_key,
  unwrap_key,
  compat: {
    algos,
    decode_data,
    convert_password,
    compute_hash,
    gost_kdf,
    gost_unwrap,
    gost_keywrap,
    gost_decrypt_cfb,
    gost_encrypt_cfb,
  },
};
