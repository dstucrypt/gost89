import {Gost} from './gost89';
import {Buffer} from './types';

const WRAP_IV = Buffer.from([0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05]);

export const wrap_key = (cek: Buffer, kek: Buffer, iv: Buffer) => {
  let idx;
  const gost = new Gost();
  const cekicv = Buffer.alloc(40);
  const temp2 = Buffer.alloc(44);
  const temp3 = Buffer.alloc(48);

  const icv = Buffer.alloc(cek.length);
  gost.key(kek);
  gost.mac(32, cek, icv);

  for (idx = 0; idx < 32; idx++) {
    cekicv[idx] = cek[idx];
  }
  for (idx = 32; idx < 40; idx++) {
    cekicv[idx] = icv[idx - 32] || 0;
  }

  const temp1 = Buffer.alloc(cekicv.length);
  gost.crypt_cfb(iv, cekicv, temp1);

  for (idx = 0; idx < 8; idx++) {
    temp2[idx] = iv[idx];
  }
  for (idx = 8; idx < 44; idx++) {
    temp2[idx] = temp1[idx - 8];
  }

  for (idx = 0; idx < 48; idx++) {
    temp3[idx] = temp2[44 - idx - 1];
  }

  const result = Buffer.alloc(temp3.length);
  gost.crypt_cfb(WRAP_IV, temp3, result);

  return Buffer.from(result.slice(0, 44));
};

export const unwrap_key = (wcek: Buffer, kek: Buffer) => {
  let idx, err;
  const gost = new Gost();

  const icv = Buffer.alloc(4);
  const iv = Buffer.alloc(8);
  const temp1 = Buffer.alloc(40);
  const temp2 = Buffer.alloc(44);
  gost.key(kek);

  const temp3 = Buffer.alloc(wcek.length);
  gost.decrypt_cfb(WRAP_IV, wcek, temp3);

  for (idx = 0; idx < 44; idx++) {
    temp2[idx] = temp3[44 - idx - 1];
  }

  for (idx = 0; idx < 8; idx++) {
    iv[idx] = temp2[idx];
  }
  for (idx = 0; idx < 36; idx++) {
    temp1[idx] = temp2[idx + 8];
  }

  const cekicv = Buffer.alloc(temp1.length);
  gost.decrypt_cfb(iv, temp1, cekicv);

  for (idx = 0; idx < 4; idx++) {
    icv[idx] = cekicv[idx + 32];
  }

  const temp = cekicv.slice(0, 32);
  const icv_check = Buffer.alloc(32);
  gost.mac(32, temp, icv_check);

  err = icv[0] ^ icv_check[0];
  err |= icv[1] ^ icv_check[1];
  err |= icv[2] ^ icv_check[2];
  err |= icv[3] ^ icv_check[3];

  if (err !== 0) {
    throw new Error('Key unwrap_key failed. Checksum mismatch');
  }

  return Buffer.from(cekicv.slice(0, 32));
};
