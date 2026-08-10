#!/usr/bin/env node
// index.html의 ENC ciphertext를 복호화해 평문 백업 파일로 만든다 (encrypt.mjs의 역연산).
// 사용: node tools/decrypt.mjs [password] [path/to/index.html] [path/to/output.html]
import { readFileSync, writeFileSync } from 'node:fs';

const PW   = process.argv[2] || 'nlolworlds2026';
const FILE = process.argv[3] || new URL('../index.html', import.meta.url).pathname;
const OUT  = process.argv[4] || new URL('../_plaintext_backup_index.html', import.meta.url).pathname;
const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder();

async function deriveKey(pw, salt){
  const base = await subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey({ name:'PBKDF2', salt, iterations:250000, hash:'SHA-256' },
    base, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']);
}
function b64ToBuf(b64){ return new Uint8Array(Buffer.from(b64,'base64')); }

const html = readFileSync(FILE, 'utf8');
const encRe = /\/\*ENC-START\*\/const ENC_SALT="([^"]*)",ENC_IV="([^"]*)",ENC_DATA="([^"]*)";\/\*ENC-END\*\//;
const m = html.match(encRe);
if(!m){ console.error('ERROR: ENC-START 블록을 찾지 못했습니다.'); process.exit(1); }
const [, saltB64, ivB64, dataB64] = m;

const key = await deriveKey(PW, b64ToBuf(saltB64));
const plainBuf = await subtle.decrypt({ name:'AES-GCM', iv:b64ToBuf(ivB64) }, key, b64ToBuf(dataB64));
const deckInner = td.decode(plainBuf);

const deckRe = /<div class="deck"><\/div><!-- \/\.deck -->/;
if(!deckRe.test(html)){ console.error('ERROR: 빈 <div class="deck"></div> 블록을 찾지 못했습니다.'); process.exit(1); }
const out = html.replace(deckRe, () => `<div class="deck">${deckInner}\n</div><!-- /.deck -->`);

writeFileSync(OUT, out, 'utf8');
console.log(`OK: 복호화 완료 → ${OUT}`);
console.log(`  ciphertext(base64) ${dataB64.length} chars → 평문 ${deckInner.length} chars`);
