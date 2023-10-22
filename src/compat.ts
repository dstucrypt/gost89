import {Buffer, ParsedData, EncodedData, ConvertPasswordParsed} from './types';
import {Gost} from './gost89';
import {dumb_kdf, pbkdf} from './util';
import {defaultSbox, packSbox} from './dstu';
import {gosthash} from './hash';
import {unwrap_key, wrap_key} from './keywrap';

export const convert_password = (
  parsed: ConvertPasswordParsed,
  pw: Buffer
): Buffer => {
  if (parsed.format === 'IIT') {
    return dumb_kdf(pw, 10000);
  }
  if (parsed.format === 'PBES2') {
    return pbkdf(pw, parsed.salt, parsed.iters);
  }

  throw new Error('Failed to convert key');
};

export const decode_data = (parsed: ParsedData, pw: Buffer): Buffer => {
  const ctx = new Gost();
  let buf, obuf;
  const bkey = convert_password(parsed, pw);
  ctx.key(bkey);

  if (parsed.format === 'IIT') {
    buf = Buffer.concat([parsed.body, parsed.pad]);
    obuf = Buffer.alloc(buf.length);
    ctx.decrypt(buf, obuf);
    return obuf.slice(0, parsed.body.length);
  }
  if (parsed.format === 'PBES2') {
    buf = parsed.body;
    obuf = Buffer.alloc(buf.length);
    ctx.decrypt_cfb(parsed.iv, buf, obuf);
    return obuf;
  }

  throw new Error('Failed to decode data');
};

export const encode_data = (
  raw: Buffer,
  format: string,
  pw: Buffer,
  iv: Buffer,
  salt: Buffer
): EncodedData => {
  const ctx = new Gost();
  if (format === 'PBES2') {
    const iters = 10000;
    const sbox = packSbox(defaultSbox);
    const bkey = convert_password({iters, salt, format}, pw);
    ctx.key(bkey);
    const obuf = Buffer.alloc(raw.length);
    ctx.crypt_cfb(iv, raw, obuf);
    return {format, iv, salt, iters, body: obuf, sbox};
  }

  throw new Error('failed to encode data');
};

export const compute_hash = (contents: Buffer) => gosthash(contents);

export const gost_unwrap = (kek: Buffer, inp: Buffer) => unwrap_key(inp, kek);

export const gost_keywrap = (kek: Buffer, inp: Buffer, iv: Buffer) =>
  wrap_key(inp, kek, iv);

export const gost_kdf = (buffer: Buffer) => compute_hash(buffer);

const gost_crypt = (mode: number, inp: Buffer, key: Buffer, iv: Buffer) => {
  const ctx = new Gost();
  const ret = Buffer.alloc(inp.length);

  ctx.key(key);
  if (mode) {
    ctx.decrypt_cfb(iv, inp, ret);
    return ret;
  } else {
    ctx.crypt_cfb(iv, inp, ret);
    return ret;
  }
};

export const gost_decrypt_cfb = (cypher: Buffer, key: Buffer, iv: Buffer) =>
  gost_crypt(1, cypher, key, iv);

export const gost_encrypt_cfb = (cypher: Buffer, key: Buffer, iv: Buffer) =>
  gost_crypt(0, cypher, key, iv);

export const algos = () => ({
  kdf: gost_kdf,
  keywrap: gost_keywrap,
  keyunwrap: gost_unwrap,
  encrypt: gost_encrypt_cfb,
  decrypt: gost_decrypt_cfb,
  hash: compute_hash,
  storeload: decode_data,
  storesave: encode_data,
});
