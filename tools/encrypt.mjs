#!/usr/bin/env node
// 최초/재빌드용: index.html의 평문 .deck을 AES-GCM으로 암호화한 발행본으로 덮어쓴다.
// 브라우저 측 decryptDeck()과 동일 파라미터 (PBKDF2 SHA-256 250k iters → AES-GCM-256).
// 사용: node tools/encrypt.mjs [password] [path/to/index.html]
import { readFileSync, writeFileSync } from 'node:fs';

const PW   = process.argv[2] || 'nlolworlds2026';
const FILE = process.argv[3] || new URL('../index.html', import.meta.url).pathname;
const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();

async function deriveKey(pw, salt){
  const base = await subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey({ name:'PBKDF2', salt, iterations:250000, hash:'SHA-256' },
    base, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']);
}
async function encryptDeck(pw, text){
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const iv   = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveKey(pw, salt);
  const ct   = await subtle.encrypt({ name:'AES-GCM', iv }, key, te.encode(text));
  const b64  = u => Buffer.from(u).toString('base64');
  return { salt:b64(salt), iv:b64(iv), data:b64(new Uint8Array(ct)) };
}

const html = readFileSync(FILE, 'utf8');

// 1) .deck innerHTML 추출
const deckRe = /<div class="deck">([\s\S]*?)\n<\/div><!-- \/\.deck -->/;
const m = html.match(deckRe);
if(!m){ console.error('ERROR: <div class="deck"> 블록을 찾지 못했습니다.'); process.exit(1); }
const deckInner = m[1];
if(deckInner.trim().length === 0){ console.error('ERROR: deck이 이미 비어 있습니다 (이미 암호화됨?).'); process.exit(1); }

// 2) 암호화
const enc = await encryptDeck(PW, deckInner);

// 3) deck 비우고 ENC 블록 채우기
let out = html.replace(deckRe, '<div class="deck"></div><!-- /.deck -->');
const encRe = /\/\*ENC-START\*\/[\s\S]*?\/\*ENC-END\*\//;
if(!encRe.test(out)){ console.error('ERROR: ENC-START 블록을 찾지 못했습니다.'); process.exit(1); }
const repl = `/*ENC-START*/const ENC_SALT="${enc.salt}",ENC_IV="${enc.iv}",ENC_DATA="${enc.data}";/*ENC-END*/`;
out = out.replace(encRe, () => repl);

writeFileSync(FILE, out, 'utf8');
console.log(`OK: 암호화 완료 → ${FILE}`);
console.log(`  deck 평문 ${deckInner.length} chars → ciphertext(base64) ${enc.data.length} chars`);
console.log(`  비밀번호: ${PW}`);
