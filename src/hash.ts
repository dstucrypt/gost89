import {Gost} from './gost89';
import {Buffer} from 'buffer';

export class Hash {
  private readonly gost: Gost;
  private left: Buffer | null;
  private len: number;
  private readonly U: Buffer;
  private readonly W: Buffer;
  private readonly V: Buffer;
  private readonly _S: Buffer;
  private readonly Key: Buffer;
  private readonly c8buf: Buffer;
  private readonly H: Buffer;
  private readonly S: Buffer;
  private readonly buf: Buffer;
  private readonly ab2: Int32Array;

  constructor() {
    this.gost = new Gost();
    this.left = null;
    this.len = 0;

    const hash_mem = Buffer.alloc(264);

    this.U = hash_mem.slice(0, 32);
    this.W = hash_mem.slice(32, 64);
    this.V = hash_mem.slice(64, 96);
    this._S = hash_mem.slice(96, 128);
    this.Key = hash_mem.slice(128, 160);
    this.c8buf = hash_mem.slice(160, 168);
    this.H = hash_mem.slice(168, 200);
    this.S = hash_mem.slice(200, 232);
    this.buf = hash_mem.slice(232, 264);

    this.ab2 = new Int32Array(4);
  }

  private static swap_bytes(w: Buffer, k: Buffer) {
    let i, j;
    for (i = 0; i < 4; i++) {
      for (j = 0; j < 8; j++) {
        k[i + 4 * j] = w[8 * i + j];
      }
    }
  }

  private circle_xor8(w: Buffer, k: Buffer) {
    const c8buf = this.c8buf;
    let i;
    for (i = 0; i < 8; i++) {
      c8buf[i] = w[i];
    }
    for (i = 0; i < 24; i++) {
      k[i] = w[i + 8];
    }
    for (i = 0; i < 8; i++) {
      k[i + 24] = c8buf[i] ^ k[i];
    }
  }

  private static transform_3(data: Buffer) {
    let i;
    const t16 =
      (data[0] ^ data[2] ^ data[4] ^ data[6] ^ data[24] ^ data[30]) |
      ((data[1] ^ data[3] ^ data[5] ^ data[7] ^ data[25] ^ data[31]) << 8);

    for (i = 0; i < 30; i++) {
      data[i] = data[i + 2];
    }
    data[30] = t16 & 0xff;
    data[31] = t16 >>> 8;
  }

  private add_blocks(n: number, left: Buffer, right: Buffer) {
    const ab2 = this.ab2;
    ab2[2] = 0;
    ab2[3] = 0;
    let i;
    for (i = 0; i < n; i++) {
      ab2[0] = left[i];
      ab2[1] = right[i];
      ab2[2] = ab2[0] + ab2[1] + ab2[3];
      left[i] = ab2[2] & 0xff;
      ab2[3] = ab2[2] >>> 8;
    }

    return ab2[3];
  }

  /* Xor two sequences of bytes */
  private static xor_blocks(ret: Buffer, a: Buffer, b: Buffer) {
    for (let i = 0; i < a.length; i++) {
      ret[i] = a[i] ^ b[i];
    }
  }

  /*
   *     Calculate H(i+1) = Hash(Hi,Mi)
   *     Where H and M are 32 bytes long
   */

  private step(H: Buffer, M: Buffer) {
    const U = this.U,
      W = this.W,
      V = this.V,
      S = this._S,
      Key = this.Key;

    const gost = this.gost;

    let i;
    /* Compute first key */
    Hash.xor_blocks(W, H, M);
    Hash.swap_bytes(W, Key);
    /* Encrypt first 8 bytes of H with first key*/
    gost.key(Key);
    gost.crypt64(H, S);
    /* Compute second key*/
    this.circle_xor8(H, U);
    this.circle_xor8(M, V);
    this.circle_xor8(V, V);
    Hash.xor_blocks(W, U, V);
    Hash.swap_bytes(W, Key);
    /* encrypt second 8 bytes of H with second key*/
    gost.key(Key);
    gost.crypt64(H.subarray(8, 16), S.subarray(8, 16));
    /* compute third key */
    this.circle_xor8(U, U);
    U[31] = ~U[31];
    U[29] = ~U[29];
    U[28] = ~U[28];
    U[24] = ~U[24];
    U[23] = ~U[23];
    U[20] = ~U[20];
    U[18] = ~U[18];
    U[17] = ~U[17];
    U[14] = ~U[14];
    U[12] = ~U[12];
    U[10] = ~U[10];
    U[8] = ~U[8];
    U[7] = ~U[7];
    U[5] = ~U[5];
    U[3] = ~U[3];
    U[1] = ~U[1];
    this.circle_xor8(V, V);
    this.circle_xor8(V, V);
    Hash.xor_blocks(W, U, V);
    Hash.swap_bytes(W, Key);
    /* encrypt third 8 bytes of H with third key*/
    gost.key(Key);
    gost.crypt64(H.subarray(16, 24), S.subarray(16, 24));
    /* Compute fourth key */
    this.circle_xor8(U, U);
    this.circle_xor8(V, V);
    this.circle_xor8(V, V);
    Hash.xor_blocks(W, U, V);
    Hash.swap_bytes(W, Key);
    /* Encrypt last 8 bytes with fourth key */
    gost.key(Key);
    gost.crypt64(H.subarray(24, 32), S.subarray(24, 32));
    for (i = 0; i < 12; i++) {
      Hash.transform_3(S);
    }

    Hash.xor_blocks(S, S, M);
    Hash.transform_3(S);
    Hash.xor_blocks(S, S, H);

    for (i = 0; i < 61; i++) {
      Hash.transform_3(S);
    }

    for (i = 0; i < 32; i++) {
      H[i] = S[i];
    }

    return 1;
  }

  update(block: Buffer): void {
    if (this.left) {
      block = Buffer.concat([this.left, block]);
    }
    let block32 = block;
    let off = 0;
    while (block.length - off >= 32) {
      this.step(this.H, block32);
      this.add_blocks(32, this.S, block32);
      off += 32;
      block32 = block.slice(off, off + 32);
    }
    this.len += off;

    if (block32.length > 0) {
      this.left = Buffer.from(block32);
    }
  }

  update32(block32: Buffer) {
    this.step(this.H, block32);
    this.add_blocks(32, this.S, block32);
    this.len += 32;
  }

  finish(hashval: Buffer): Buffer {
    const buf = this.buf;
    let fin_len = this.len;
    let idx = 0;

    if (this.left) {
      for (idx = 0; idx < this.left.length; idx++) {
        buf[idx] = this.left[idx];
      }
      this.step(this.H, buf);
      this.add_blocks(32, this.S, buf);
      fin_len += this.left.length;
      this.left = null;

      for (idx = 0; idx < 32; idx++) {
        buf[idx] = 0;
      }
    }

    fin_len <<= 3;
    idx = 0;
    while (fin_len > 0) {
      buf[idx++] = fin_len & 0xff;
      fin_len >>= 8;
    }

    this.step(this.H, buf);
    this.step(this.H, this.S);

    for (idx = 0; idx < 32; idx++) {
      hashval[idx] = this.H[idx];
    }
    return hashval;
  }

  reset(): void {
    let idx;
    for (idx = 0; idx < 32; idx++) {
      this.H[idx] = 0;
      this.S[idx] = 0;
    }
    this.left = null;
    this.len = 0;
  }
}

export const gosthash = (data: Buffer, ret?: Buffer): Buffer => {
  const ctx = new Hash();
  ctx.update(data);
  if (ret === undefined) {
    ret = Buffer.alloc(32);
  }
  return Buffer.from(ctx.finish(ret));
};
