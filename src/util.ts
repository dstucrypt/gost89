import {Hash} from './hash';
import {Buffer} from './types';

export const dumb_kdf = (input: Buffer, n_passes: number): Buffer => {
  const ctx = new Hash();
  const hash = Buffer.alloc(32);

  ctx.update(input);
  ctx.finish(hash);

  n_passes--;

  while (n_passes--) {
    ctx.reset();
    ctx.update32(hash);
    ctx.finish(hash);
  }

  return Buffer.from(hash);
};

export const pbkdf = (input: Buffer, salt: Buffer, iters: number): Buffer => {
  const hash = Buffer.alloc(32);
  const key = Buffer.alloc(32);
  const pw_pad36 = Buffer.alloc(32);
  const pw_pad5C = Buffer.alloc(32);

  const ctx = new Hash();

  const ins = Buffer.alloc(4);
  ins[3] = 1;

  let k;
  for (k = 0; k < 32; k++) {
    pw_pad36[k] = 0x36;
    pw_pad5C[k] = 0x5c;
  }
  for (k = 0; k < input.length; k++) {
    pw_pad36[k] ^= input[k];
  }
  for (k = 0; k < input.length; k++) {
    pw_pad5C[k] ^= input[k];
  }

  ctx.update32(pw_pad36);
  ctx.update(salt);
  ctx.update(ins);
  ctx.finish(hash);

  ctx.reset();

  ctx.update32(pw_pad5C);
  ctx.update32(hash);
  ctx.finish(hash);

  iters--;

  for (k = 0; k < 32; k++) {
    key[k] = hash[k];
  }

  while (iters-- > 0) {
    ctx.reset();
    ctx.update32(pw_pad36);
    ctx.update32(hash);
    ctx.finish(hash);

    ctx.reset();
    ctx.update32(pw_pad5C);
    ctx.update32(hash);
    ctx.finish(hash);

    for (k = 0; k < 32; k++) {
      key[k] ^= hash[k];
    }
  }

  return Buffer.from(key);
};
