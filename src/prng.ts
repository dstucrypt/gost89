import {Gost} from './gost89';
import {Buffer} from './types';

export class PRNG {
  private readonly counter: Buffer;
  private readonly ctx: Gost;
  private readonly I: Buffer;
  private readonly X: Buffer;

  constructor(key: Buffer) {
    this.ctx = new Gost();
    this.counter = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0]);
    this.I = Buffer.alloc(8);
    this.X = Buffer.alloc(8);
    this.ctx.key(key);
  }

  static seed(seed: Buffer): PRNG {
    return new PRNG(seed);
  }

  next(bytes: number): Buffer {
    let off = 0;
    const rb = Buffer.alloc(bytes);
    let step;
    while (bytes > off) {
      step = this.value();
      step.copy(rb, off);
      off += step.length;
    }
    return rb;
  }

  private increment(): void {
    let idx;
    let zero = 0;
    const len = 8;
    for (idx = 0; idx < len; idx++) {
      this.counter[idx]++;
      if (this.counter[idx] > 0) {
        break;
      }

      zero = idx - 1;
    }
    for (idx = 0; idx < zero; idx++) {
      this.counter[idx] = 0;
    }
  }

  private bit(): Buffer {
    let idx;
    this.ctx.crypt64(this.counter, this.I);
    for (idx = 0; idx < 8; idx++) {
      this.I[idx] ^= this.counter[idx];
    }
    this.ctx.crypt64(this.I, this.X);

    const ret = Buffer.from(this.X);

    for (idx = 0; idx < 8; idx++) {
      this.X[idx] ^= this.I[idx];
    }
    this.ctx.crypt64(this.X, this.counter);

    this.increment();
    return ret;
  }

  private value(): Buffer {
    const ret = Buffer.alloc(8);
    let idx, bidx;
    let step;

    for (idx = 0; idx < 8; idx++) {
      for (bidx = 0; bidx < 8; bidx++) {
        step = this.bit();
        ret[idx] |= (step[0] & 1) << bidx;
      }
    }

    return ret;
  }
}
