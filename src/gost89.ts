import {Buffer} from './types';
import {defaultSbox} from './dstu';

export class SBox {
  readonly k1: Uint32Array;
  readonly k2: Uint32Array;
  readonly k3: Uint32Array;
  readonly k4: Uint32Array;
  readonly k5: Uint32Array;
  readonly k6: Uint32Array;
  readonly k7: Uint32Array;
  readonly k8: Uint32Array;

  constructor(data: Buffer, mem: Uint32Array) {
    this.k8 = mem.subarray(0, 16);
    this.k7 = mem.subarray(16, 32);
    this.k6 = mem.subarray(32, 48);
    this.k5 = mem.subarray(48, 64);
    this.k4 = mem.subarray(64, 80);
    this.k3 = mem.subarray(80, 96);
    this.k2 = mem.subarray(96, 112);
    this.k1 = mem.subarray(112, 128);

    let idx;

    for (idx = 0; idx < mem.length; idx++) {
      mem[idx] = data[idx];
    }
  }
}

export class Gost {
  private readonly k: Uint32Array;
  private readonly k87: Uint32Array;
  private readonly k65: Uint32Array;
  private readonly k43: Uint32Array;
  private readonly k21: Uint32Array;
  private readonly n: Uint32Array;
  private gamma: Uint8Array;

  constructor(sbox?: SBox | Buffer) {
    const mem = new Uint32Array(1162);

    this.k = mem.subarray(0, 8);
    this.k87 = mem.subarray(8, 264);
    this.k65 = mem.subarray(264, 520);
    this.k43 = mem.subarray(520, 776);
    this.k21 = mem.subarray(776, 1032);
    this.n = mem.subarray(1160, 1162);
    this.gamma = Buffer.alloc(8);

    if (sbox === undefined) {
      sbox = defaultSbox;
    }

    if (!(sbox instanceof SBox)) {
      sbox = new SBox(sbox!, mem.subarray(1032, 1160));
    }

    this.boxinit(sbox);
  }

  private boxinit(sbox: SBox): void {
    let i;

    for (i = 0; i < 256; i++) {
      this.k87[i] = ((sbox.k8[i >>> 4] << 4) | sbox.k7[i & 15]) << 24;
      this.k65[i] = ((sbox.k6[i >>> 4] << 4) | sbox.k5[i & 15]) << 16;
      this.k43[i] = ((sbox.k4[i >>> 4] << 4) | sbox.k3[i & 15]) << 8;
      this.k21[i] = (sbox.k2[i >>> 4] << 4) | sbox.k1[i & 15];
    }
  }

  pass(x: number): number {
    x =
      this.k87[(x >>> 24) & 255] |
      this.k65[(x >>> 16) & 255] |
      this.k43[(x >>> 8) & 255] |
      this.k21[x & 255];
    /* Rotate left 11 bits */
    return (x << 11) | (x >>> (32 - 11));
  }

  crypt64(clear: Uint8Array, out: Buffer | Uint8Array): void {
    const n = this.n;
    n[0] = clear[0] | (clear[1] << 8) | (clear[2] << 16) | (clear[3] << 24);
    n[1] = clear[4] | (clear[5] << 8) | (clear[6] << 16) | (clear[7] << 24);
    /* Instead of swappclearg halves, swap names each round */

    n[1] ^= this.pass(n[0] + this.k[0]);
    n[0] ^= this.pass(n[1] + this.k[1]);
    n[1] ^= this.pass(n[0] + this.k[2]);
    n[0] ^= this.pass(n[1] + this.k[3]);
    n[1] ^= this.pass(n[0] + this.k[4]);
    n[0] ^= this.pass(n[1] + this.k[5]);
    n[1] ^= this.pass(n[0] + this.k[6]);
    n[0] ^= this.pass(n[1] + this.k[7]);

    n[1] ^= this.pass(n[0] + this.k[0]);
    n[0] ^= this.pass(n[1] + this.k[1]);
    n[1] ^= this.pass(n[0] + this.k[2]);
    n[0] ^= this.pass(n[1] + this.k[3]);
    n[1] ^= this.pass(n[0] + this.k[4]);
    n[0] ^= this.pass(n[1] + this.k[5]);
    n[1] ^= this.pass(n[0] + this.k[6]);
    n[0] ^= this.pass(n[1] + this.k[7]);

    n[1] ^= this.pass(n[0] + this.k[0]);
    n[0] ^= this.pass(n[1] + this.k[1]);
    n[1] ^= this.pass(n[0] + this.k[2]);
    n[0] ^= this.pass(n[1] + this.k[3]);
    n[1] ^= this.pass(n[0] + this.k[4]);
    n[0] ^= this.pass(n[1] + this.k[5]);
    n[1] ^= this.pass(n[0] + this.k[6]);
    n[0] ^= this.pass(n[1] + this.k[7]);

    n[1] ^= this.pass(n[0] + this.k[7]);
    n[0] ^= this.pass(n[1] + this.k[6]);
    n[1] ^= this.pass(n[0] + this.k[5]);
    n[0] ^= this.pass(n[1] + this.k[4]);
    n[1] ^= this.pass(n[0] + this.k[3]);
    n[0] ^= this.pass(n[1] + this.k[2]);
    n[1] ^= this.pass(n[0] + this.k[1]);
    n[0] ^= this.pass(n[1] + this.k[0]);

    out[0] = n[1] & 0xff;
    out[1] = (n[1] >>> 8) & 0xff;
    out[2] = (n[1] >>> 16) & 0xff;
    out[3] = n[1] >>> 24;
    out[4] = n[0] & 0xff;
    out[5] = (n[0] >>> 8) & 0xff;
    out[6] = (n[0] >>> 16) & 0xff;
    out[7] = n[0] >>> 24;
  }

  decrypt64(crypt: Uint8Array, out: Buffer): void {
    const n = this.n;
    n[0] = crypt[0] | (crypt[1] << 8) | (crypt[2] << 16) | (crypt[3] << 24);
    n[1] = crypt[4] | (crypt[5] << 8) | (crypt[6] << 16) | (crypt[7] << 24);

    n[1] ^= this.pass(n[0] + this.k[0]);
    n[0] ^= this.pass(n[1] + this.k[1]);
    n[1] ^= this.pass(n[0] + this.k[2]);
    n[0] ^= this.pass(n[1] + this.k[3]);
    n[1] ^= this.pass(n[0] + this.k[4]);
    n[0] ^= this.pass(n[1] + this.k[5]);
    n[1] ^= this.pass(n[0] + this.k[6]);
    n[0] ^= this.pass(n[1] + this.k[7]);

    n[1] ^= this.pass(n[0] + this.k[7]);
    n[0] ^= this.pass(n[1] + this.k[6]);
    n[1] ^= this.pass(n[0] + this.k[5]);
    n[0] ^= this.pass(n[1] + this.k[4]);
    n[1] ^= this.pass(n[0] + this.k[3]);
    n[0] ^= this.pass(n[1] + this.k[2]);
    n[1] ^= this.pass(n[0] + this.k[1]);
    n[0] ^= this.pass(n[1] + this.k[0]);

    n[1] ^= this.pass(n[0] + this.k[7]);
    n[0] ^= this.pass(n[1] + this.k[6]);
    n[1] ^= this.pass(n[0] + this.k[5]);
    n[0] ^= this.pass(n[1] + this.k[4]);
    n[1] ^= this.pass(n[0] + this.k[3]);
    n[0] ^= this.pass(n[1] + this.k[2]);
    n[1] ^= this.pass(n[0] + this.k[1]);
    n[0] ^= this.pass(n[1] + this.k[0]);

    n[1] ^= this.pass(n[0] + this.k[7]);
    n[0] ^= this.pass(n[1] + this.k[6]);
    n[1] ^= this.pass(n[0] + this.k[5]);
    n[0] ^= this.pass(n[1] + this.k[4]);
    n[1] ^= this.pass(n[0] + this.k[3]);
    n[0] ^= this.pass(n[1] + this.k[2]);
    n[1] ^= this.pass(n[0] + this.k[1]);
    n[0] ^= this.pass(n[1] + this.k[0]);

    out[0] = n[1] & 0xff;
    out[1] = (n[1] >>> 8) & 0xff;
    out[2] = (n[1] >>> 16) & 0xff;
    out[3] = n[1] >>> 24;
    out[4] = n[0] & 0xff;
    out[5] = (n[0] >>> 8) & 0xff;
    out[6] = (n[0] >>> 16) & 0xff;
    out[7] = n[0] >>> 24;
  }

  crypt64_cfb(iv: Uint8Array, clear: Buffer, out: Buffer): void {
    let j;
    const gamma = this.gamma;

    this.crypt64(iv, gamma);
    for (j = 0; j < 8; j++) {
      out[j] = clear[j] ^ gamma[j];
      iv[j] = out[j];
    }
  }

  decrypt64_cfb(iv: Uint8Array, ctext: Buffer, clear: Buffer): void {
    let j;
    const gamma = this.gamma;

    this.crypt64(iv, gamma);
    for (j = 0; j < 8; j++) {
      iv[j] = ctext[j];
      clear[j] = ctext[j] ^ gamma[j];
    }
  }

  crypt_cfb(iv: Uint8Array, clear: Buffer, out: Buffer): void {
    const blocks = Math.ceil(clear.length / 8);
    let idx;
    let off;

    this.gamma = Buffer.alloc(8);
    const curIV = Buffer.alloc(8);
    for (idx = 0; idx < 8; idx++) {
      curIV[idx] = iv[idx];
    }

    idx = 0;
    while (idx < blocks) {
      off = idx++ * 8;
      this.crypt64_cfb(
        curIV,
        clear.slice(off, off + 8),
        out.slice(off, off + 8)
      );
    }
    if (out.length !== clear.length) {
      out = Buffer.from(out.slice(0, clear.length));
    }
  }

  decrypt_cfb(iv: Buffer, ctext: Buffer, out: Buffer): void {
    const blocks = Math.ceil(ctext.length / 8);
    let idx;
    let off;

    this.gamma = Buffer.alloc(8);
    const curIV = Buffer.alloc(8);
    for (idx = 0; idx < 8; idx++) {
      curIV[idx] = iv[idx];
    }

    idx = 0;
    while (idx < blocks) {
      off = idx++ * 8;
      this.decrypt64_cfb(
        curIV,
        ctext.slice(off, off + 8),
        out.slice(off, off + 8)
      );
    }
    if (out.length !== ctext.length) {
      out = Buffer.from(out.slice(0, ctext.length));
    }
  }

  crypt(clear: Buffer, out: Buffer): Buffer {
    const blocks = Math.ceil(clear.length / 8);
    let off;
    let idx;

    if (!Buffer.isBuffer(clear)) {
      clear = Buffer.from(clear, 'binary');
    }
    if (!out) {
      out = Buffer.alloc(blocks * 8);
    }
    if (!Buffer.isBuffer(out)) {
      throw new Error('Either pass output buffer or nothing');
    }

    idx = 0;
    while (idx < blocks) {
      off = idx++ * 8;
      this.crypt64(clear.slice(off, off + 8), out.slice(off, off + 8));
    }

    if (out.length !== clear.length) {
      out = Buffer.from(out.slice(0, clear.length));
    }
    return out;
  }

  decrypt(cypher: Buffer, clear: Buffer): Buffer {
    let blocks = Math.ceil(cypher.length / 8);
    let off;

    if (!Buffer.isBuffer(clear)) {
      clear = Buffer.alloc(blocks * 8);
    }
    if (!Buffer.isBuffer(cypher)) {
      cypher = Buffer.from(cypher, 'binary');
    }

    while (blocks--) {
      off = blocks * 8;
      this.decrypt64(cypher.slice(off, off + 8), clear.slice(off, off + 8));
    }

    if (clear.length !== cypher.length) {
      clear = Buffer.from(clear.slice(0, cypher.length));
    }
    return clear;
  }

  key(k: Buffer): void {
    let i, j;
    for (i = 0, j = 0; i < 8; i++, j += 4) {
      this.k[i] = k[j] | (k[j + 1] << 8) | (k[j + 2] << 16) | (k[j + 3] << 24);
    }
  }

  mac(len: number, data: Buffer, out: Buffer) {
    const buf = Buffer.alloc(8);
    const buf2 = Buffer.alloc(8);

    let i;
    for (i = 0; i + 8 <= data.length; i += 8) {
      this.mac64(buf, data.slice(i, i + 8));
    }

    if (i < data.length) {
      data = data.slice(i);
      for (i = 0; i < data.length; i++) {
        buf2[i] = data[i];
      }
      this.mac64(buf, buf2);
    }

    if (i === 8) {
      for (i = 0; i < buf2.length; i++) {
        buf2[i] = 0;
      }
      this.mac64(buf, buf2);
    }

    Gost.mac_out(buf, len, out);
  }

  private static mac_out(buf: Uint8Array, nbits: number, out: Buffer): void {
    const nBuffer = nbits >>> 3;
    const rembits = nbits & 7;
    const mask = rembits ? Number(1 < rembits) - 1 : 0;
    let i;
    if (typeof out === 'undefined') {
      out = Buffer.alloc(nBuffer);
    }
    if (!Buffer.isBuffer(out)) {
      throw new Error('Either pass output buffer or nothing');
    }
    for (i = 0; i < nBuffer; i++) {
      out[i] = buf[i];
    }
    if (rembits) {
      out[i] = buf[i] & mask;
    }
  }

  private mac64(buffer: Uint8Array, block: Uint8Array) {
    const n = this.n;
    for (let i = 0; i < 8; i++) {
      buffer[i] ^= block[i];
    }
    n[0] = buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24);
    n[1] = buffer[4] | (buffer[5] << 8) | (buffer[6] << 16) | (buffer[7] << 24);
    /* Instead of swapping halves, swap names each round */

    n[1] ^= this.pass(n[0] + this.k[0]);
    n[0] ^= this.pass(n[1] + this.k[1]);
    n[1] ^= this.pass(n[0] + this.k[2]);
    n[0] ^= this.pass(n[1] + this.k[3]);
    n[1] ^= this.pass(n[0] + this.k[4]);
    n[0] ^= this.pass(n[1] + this.k[5]);
    n[1] ^= this.pass(n[0] + this.k[6]);
    n[0] ^= this.pass(n[1] + this.k[7]);

    n[1] ^= this.pass(n[0] + this.k[0]);
    n[0] ^= this.pass(n[1] + this.k[1]);
    n[1] ^= this.pass(n[0] + this.k[2]);
    n[0] ^= this.pass(n[1] + this.k[3]);
    n[1] ^= this.pass(n[0] + this.k[4]);
    n[0] ^= this.pass(n[1] + this.k[5]);
    n[1] ^= this.pass(n[0] + this.k[6]);
    n[0] ^= this.pass(n[1] + this.k[7]);

    buffer[0] = n[0] & 0xff;
    buffer[1] = (n[0] >>> 8) & 0xff;
    buffer[2] = (n[0] >>> 16) & 0xff;
    buffer[3] = n[0] >>> 24;
    buffer[4] = n[1] & 0xff;
    buffer[5] = (n[1] >>> 8) & 0xff;
    buffer[6] = (n[1] >>> 16) & 0xff;
    buffer[7] = n[1] >>> 24;
  }
}
