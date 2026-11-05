'use strict';

import { call, pattern, custom, WEB, JVM, ALLL, fileText } from './helpers.js';
import { m, x } from './injection.js';
// The repository's own secret scanner (Trivy-derived ruleset + entropy + allow-rules).
// SAST does not carry a second, weaker detector: hardcoded-secret findings ARE its findings.
import { scanText, isPathAllowed } from '../../../../sca/secrets.js';

const CODE_FAMILIES = ['js', 'python', 'php', 'ruby', 'go', 'rust', 'java', 'kotlin', 'csharp', 'dart', 'swift', 'c'];
const SEV = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };

function secretRule(id, cls, langs) {
  return custom({
    id, cls, langs, sev: 'high', conf: 'high', group: 'secret',
    fix: 'Remove the credential from source, rotate it (treat it as compromised), and load it from the environment or a secrets manager at runtime. Purge it from git history.',
    run(flow, emit) {
      const rel = String(flow.chunk.file || '').replace(/\\/g, '/');
      if (isPathAllowed(rel)) return;                                  // tests / examples / lockfiles, as in the repo-wide secret scan
      const lines = flow.chunk.code.split(/\r\n|\r|\n/);
      let found;
      try { found = scanText(lines, rel); } catch { return; }
      for (const f of found) {
        const raw = lines[f.line - 1] || '';
        const a = Math.max(0, f.column_start - 1), b = Math.max(a, f.column_end - 1);
        const snippet = (raw.slice(0, a) + f.match_preview + raw.slice(b)).trim().slice(0, 300);   // never the raw secret
        emit(0, {
          title: `Hardcoded secret: ${f.title}`, relLine: f.line, snippet, lineNeedle: raw.trim(),
          sev: SEV[f.severity] || 'high',
          desc: `${f.title} (${f.category}) is committed in source: ${f.match_preview}. Anyone with read access to the repository can use it.`,
          fingerprint: f.fingerprint, secretRuleId: f.id,
        });
      }
    },
  });
}

const SECRET_RULES = [
  secretRule('secret-code', 'hardcoded secret or credential', CODE_FAMILIES),
  secretRule('secret-docker', 'hardcoded secret in Docker image or Compose file', ['docker']),
  secretRule('secret-iac', 'hardcoded secret in IaC template or variable', ['iac', 'k8s']),
];

// ═══ Cryptographic weakness ══════════════════════════════════════════════════
const CR = { cls: 'cryptographic weakness', sev: 'medium', conf: 'medium', group: 'crypto' };
const SEC_WORDS = /(?:password|passwd|pwd|secret|token|auth|credential|session|signature|\bsign|hmac|salt|otp|reset|api[_-]?key|secret[_-]?key|private[_-]?key|encrypt\w*[_-]?key|signing[_-]?key|login|encrypt|decrypt|cipher|verify)/i;
// Which package does `qual` (the identifier before the dot) refer to in this Go file?
function goRandIsMath(src, qual) {
  const re = /(?:^|\n)[ \t]*(?:import[ \t]+)?(?:([A-Za-z_]\w*|\.|_)[ \t]+)?"(math\/rand(?:\/v2)?|crypto\/rand)"/g;
  let m, pkg = null;
  while ((m = re.exec(src)) !== null) if ((m[1] || 'rand') === qual) pkg = m[2];
  return pkg !== null && pkg.startsWith('math/');
}
const NONSEC_WORDS = /(?:checksum|etag|cache|fingerprint|file_?hash|content_?hash|gravatar|integrity|dedup|bucket|shard|hash_?key|cache_?key|uniq|identicon|avatar|thumbnail|filename|slug|color|colour|seed_?for_?test)/i;

function useContext(cand, flow) {
  const ll = flow.ctx.logical.find(l => cand.off >= l.start && cand.off < l.end);
  const rawLine = ll ? (flow.chunk.code.split('\n')[ll.line - 1] || '') : '';       // keeps the trailing comment ("# cache key")
  const around = (ll ? ll.text : '') + ' ' + rawLine + ' ' + (flow.chunk.name || '');
  const sec = SEC_WORDS.test(around), non = NONSEC_WORDS.test(around);
  return { sec, non };
}
const hashVerify = (cand, flow) => {
  const { sec, non } = useContext(cand, flow);
  if (non && !sec) return { valid: false, reason: 'the hash is used for a non-security purpose (checksum / cache key / fingerprint)' };
  return sec ? { valid: true, conf: 'high' } : { valid: true, conf: 'low' };
};
const rngVerify = (cand, flow) => {
  const { sec, non } = useContext(cand, flow);
  const around = flow.ctx.literal.slice(Math.max(0, cand.off - 400), cand.off + 400);
  if (sec || SEC_WORDS.test(around.replace(/(?:Math\.)?random|rand/gi, ''))) return { valid: true, conf: sec ? 'high' : 'medium' };
  return { valid: false, reason: 'no security-sensitive use (token, key, password, session, salt, nonce…) is visible near this random number' };
};
const WEAK_HASH_LIT = /^["'`]?\s*(?:md5|md4|md2|sha-?1|ripemd-?160|crc32|sha1withrsa|md5withrsa)\b/i;
const WEAK_CIPHER_LIT = /^["'`]?\s*(?:des|desede|3des|tripledes|rc2|rc4|arcfour|blowfish|des-ede3|bf)(?:["'`/\-]|\b)/i;

const CRYPTO_RULES = [
  // weak hashes
  call({ ...CR, id: 'crypto-hash-python', langs: ['python'], need: 'always', what: 'uses a broken hash function (MD5/SHA-1)', verify: hashVerify,
    callee: x('hashlib\\.(?:md5|sha1|md4)|(?:MD5|SHA|SHA1|MD4|MD2)\\.new|Crypto\\.Hash\\.(?:MD5|SHA1)\\.new|md5|sha1'), allowNoArgs: true, args: 'any', title: 'Weak hash function (MD5/SHA-1)',
    fix: 'Use SHA-256 or stronger for integrity, and a password KDF (argon2id, scrypt, bcrypt, PBKDF2) for passwords. For authentication tags use HMAC-SHA-256.' }),
  call({ ...CR, id: 'crypto-hashnew-python', langs: ['python'], need: 'always', what: 'uses a broken hash function (MD5/SHA-1)', verify: hashVerify,
    callee: x('hashlib\\.new|hmac\\.new|hmac\\.digest'), when: (c) => WEAK_HASH_LIT.test(c.args[0]?.lit || '') || /(?:digestmod|digest)\s*=\s*["'`]?(?:md5|sha1)|hashlib\.(?:md5|sha1)/i.test(c.text) || (c.callee === 'hmac.new' && /\b(?:md5|sha1)\b/i.test(c.args[2]?.lit || c.text)), title: 'Weak hash function (MD5/SHA-1)' }),
  call({ ...CR, id: 'crypto-hash-js', langs: ['js'], need: 'always', what: 'uses a broken hash function (MD5/SHA-1)', verify: hashVerify,
    callee: x('(?:crypto\\.)?createHash|(?:crypto\\.)?createHmac|(?:CryptoJS\\.)?(?:MD5|SHA1)|md5|sha1|crypto\\.subtle\\.digest|createSign|createVerify'),
    when: (c) => /^(?:CryptoJS\.)?(?:MD5|SHA1)$|^(?:md5|sha1)$/.test(c.callee) || WEAK_HASH_LIT.test(c.args[0]?.lit || '') || /["']SHA-1["']/.test(c.lit), title: 'Weak hash function (MD5/SHA-1)', args: 'any' }),
  call({ ...CR, id: 'crypto-hash-php', langs: ['php'], need: 'always', what: 'uses a broken hash function (MD5/SHA-1)', verify: hashVerify, args: 'any',
    callee: x('md5|sha1|md5_file|sha1_file|crypt|hash|hash_hmac|hash_file|crc32|openssl_digest'), title: 'Weak hash function (MD5/SHA-1)',
    when: (c) => !/^(?:hash|hash_hmac|hash_file|openssl_digest)$/.test(c.callee) || WEAK_HASH_LIT.test(c.args[c.callee === 'hash_hmac' || c.callee === 'hash_file' || c.callee === 'hash' || c.callee === 'openssl_digest' ? (c.callee === 'openssl_digest' ? 1 : 0) : 0]?.lit || '') || /["'](?:md5|sha1|crc32)["']/i.test(c.lit) }),
  call({ ...CR, id: 'crypto-hash-ruby', langs: ['ruby'], need: 'always', what: 'uses a broken hash function (MD5/SHA-1)', verify: hashVerify, args: 'any', allowNoArgs: true,
    callee: x('(?:OpenSSL::)?Digest(?:::(?:MD5|SHA1|MD4))?\\.(?:new|hexdigest|digest|base64digest)|Digest::(?:MD5|SHA1)\\.(?:hexdigest|digest|base64digest|new)|OpenSSL::Digest::(?:MD5|SHA1)\\.(?:new|hexdigest|digest)|OpenSSL::HMAC\\.(?:hexdigest|digest)'),
    when: (c) => /(?:MD5|SHA1)\b/.test(c.callee) || /["'`](?:md5|sha1)["'`]/i.test(c.lit), title: 'Weak hash function (MD5/SHA-1)' }),
  call({ ...CR, id: 'crypto-hash-go', langs: ['go'], need: 'always', what: 'uses a broken hash / cipher', verify: hashVerify, args: 'any', allowNoArgs: true,
    callee: x('(?:md5|sha1|md4|ripemd160)\\.(?:New|Sum)|des\\.New(?:TripleDES)?Cipher|rc4\\.NewCipher'), title: 'Weak cryptographic primitive (MD5/SHA-1/DES/RC4)' }),
  call({ ...CR, id: 'crypto-hash-rust', langs: ['rust'], need: 'always', what: 'uses a broken hash function (MD5/SHA-1)', verify: hashVerify, args: 'any', allowNoArgs: true,
    callee: x('(?:Md5|Md4|Md2|Sha1)::(?:new|digest|default)|md5::(?:compute|Md5)|sha1::(?:Sha1|digest)|(?:openssl::hash::)?MessageDigest::(?:md5|sha1)|Hasher::new\\(\\s*MessageDigest::(?:md5|sha1)|(?:des|rc4|rc2|blowfish)::\\w+::new'), title: 'Weak hash function (MD5/SHA-1)' }),
  call({ ...CR, id: 'crypto-hash-jvm', langs: JVM, need: 'always', what: 'uses a broken hash function', verify: hashVerify, args: 'any',
    callee: x('MessageDigest\\.getInstance|(?:\\w+\\.)?(?:DigestUtils\\.(?:md5|md5Hex|sha1|sha1Hex|sha|shaHex|getMd5Digest|getSha1Digest)|Hashing\\.(?:md5|sha1))|Mac\\.getInstance|Signature\\.getInstance'),
    when: (c) => /^(?:MessageDigest|Mac|Signature)\./.test(c.callee) ? /^["']?(?:md5|md2|md4|sha-?1|hmacmd5|hmacsha1|md5withrsa|sha1withrsa|sha1withdsa)/i.test(c.args[0]?.lit.replace(/["']/g, '') ? ('"' + c.args[0].lit.replace(/["']/g, '') + '"') : '') : true, title: 'Weak hash function (MD5/SHA-1)' }),
  call({ ...CR, id: 'crypto-hash-csharp', langs: ['csharp'], need: 'always', what: 'uses a broken hash / cipher', verify: hashVerify, args: 'any', allowNoArgs: true,
    callee: x('(?:MD5|SHA1|DES|TripleDES|RC2|HMACMD5|HMACSHA1)\\.Create|MD5CryptoServiceProvider|SHA1CryptoServiceProvider|SHA1Managed|DESCryptoServiceProvider|TripleDESCryptoServiceProvider|RC2CryptoServiceProvider|HashAlgorithm\\.Create|HMACMD5|HMACSHA1|MD5|SHA1|DES|RijndaelManaged'),
    when: (c) => !/^(?:HashAlgorithm\.Create)$/.test(c.callee) || /md5|sha1/i.test(c.lit), title: 'Weak cryptographic primitive (MD5/SHA-1/DES/RC2)' }),
  call({ ...CR, id: 'crypto-hash-c', langs: ['c'], need: 'always', what: 'uses a broken hash / cipher', verify: hashVerify, args: 'any', allowNoArgs: true,
    callee: x('MD5|MD5_Init|MD5_Update|SHA1|SHA1_Init|MD4|MD2|DES_ecb_encrypt|DES_set_key|DES_crypt|des_setkey|RC4|RC4_set_key|EVP_md5|EVP_sha1|EVP_md4|EVP_des_\\w+|EVP_rc4|EVP_rc2_\\w+|EVP_bf_\\w+|EVP_\\w+_ecb|CC_MD5|CC_SHA1|crypt'), title: 'Weak cryptographic primitive (MD5/SHA-1/DES/RC4)' }),
  call({ ...CR, id: 'crypto-hash-dart', langs: ['dart'], need: 'always', what: 'uses a broken hash function (MD5/SHA-1)', verify: hashVerify, args: 'any', allowNoArgs: true,
    callee: x('(?:md5|sha1)\\.(?:convert|newInstance|bind)|(?:Md5|Sha1)\\(\\)|Hmac\\((?:md5|sha1)'), title: 'Weak hash function (MD5/SHA-1)' }),
  call({ ...CR, id: 'crypto-hash-swift', langs: ['swift'], need: 'always', what: 'uses a broken hash / cipher', verify: hashVerify, args: 'any', allowNoArgs: true,
    callee: x('CC_MD5|CC_SHA1|CC_MD5_Init|CC_SHA1_Init|Insecure\\.(?:MD5|SHA1)\\.hash|Insecure\\.(?:MD5|SHA1)|CCCrypt'), when: (c) => c.callee !== 'CCCrypt' || /kCCAlgorithmDES|kCCAlgorithm3DES|kCCAlgorithmRC4|kCCAlgorithmRC2|kCCOptionECBMode/.test(c.text), title: 'Weak cryptographic primitive (MD5/SHA-1/DES/RC4)' }),

  // weak ciphers and modes
  call({ ...CR, id: 'crypto-cipher-jvm', langs: JVM, need: 'always', what: 'selects a broken cipher or ECB mode (Java defaults "AES" to ECB)', sev: 'high', args: 'any',
    callee: x('(?:Cipher|KeyGenerator|SecretKeyFactory|KeyPairGenerator)\\.getInstance|SecretKeySpec'),
    when: (c) => { const v = (c.args[c.callee === 'SecretKeySpec' ? 1 : 0]?.lit || '').replace(/["']/g, '').trim(); return WEAK_CIPHER_LIT.test('"' + v) || /\/ECB\b|\bECB\//i.test(v) || /^AES$/i.test(v) && c.callee === 'Cipher.getInstance' || /^RSA\/ECB\/(?:NoPadding|PKCS1Padding)/i.test(v) || (c.callee === 'SecretKeySpec' && /^(?:DES|DESede|RC4|RC2|Blowfish)$/i.test(v)); },
    title: 'Weak cipher or ECB mode' }),
  call({ ...CR, id: 'crypto-cipher-js', langs: ['js'], need: 'always', what: 'selects a broken cipher or ECB mode', sev: 'high', args: 'any',
    callee: x('(?:crypto\\.)?(?:createCipheriv|createDecipheriv|createCipher|createDecipher)|(?:CryptoJS\\.)?(?:DES|TripleDES|RC4|RC4Drop|Rabbit)\\.(?:encrypt|decrypt)|CryptoJS\\.mode\\.ECB'),
    when: (c) => /^createCipher$|^createDecipher$|^crypto\.createCipher$|^crypto\.createDecipher$/.test(c.callee) || /^["'`]?(?:aes-\d+-ecb|des|des-ede3|des3|rc4|rc2|bf|blowfish)\b/i.test((c.args[0]?.lit || '').replace(/^["'`]/, '"')) && /ecb|des|rc4|rc2|bf|blowfish/i.test(c.args[0]?.lit || '') || /CryptoJS\.(?:DES|TripleDES|RC4|Rabbit)/.test(c.callee) || /mode\.ECB/.test(c.callee),
    title: 'Weak cipher or ECB mode' }),
  pattern({ ...CR, id: 'crypto-ecb-py', inString: true, langs: ['python', 'ruby', 'go', 'rust', 'csharp', 'c', 'dart', 'swift', 'php', 'kotlin'], sev: 'high', title: 'Weak cipher or ECB mode', what: 'uses ECB mode',
    re: /\b(?:AES\.MODE_ECB|MODE_ECB|DES\.new|DES3\.new|ARC4\.new|ARC2\.new|Blowfish\.new|CipherMode\.ECB|kCCOptionECBMode|AESMode\.ecb|EVP_\w+_ecb\w*|MCRYPT_MODE_ECB|OPENSSL_ZERO_PADDING|MCRYPT_DES|MCRYPT_3DES|MCRYPT_RC4|MCRYPT_BLOWFISH|des_ecb|openssl_encrypt\s*\(\s*[^,]+,\s*["'][^"']*(?:-ecb|des|rc4)[^"']*["']|aes-\d+-ecb|Cipher::DES|OpenSSL::Cipher::(?:DES|RC4|RC2|BF)|OpenSSL::Cipher\.new\s*\(\s*["'](?:des|rc4|rc2|bf|aes-\d+-ecb)[^"']*["']|des\.NewCipher|rc4\.NewCipher|des\.NewTripleDESCipher|BlockMode::Ecb|ecb::Mode|Ecb<|Aes\d+Ecb|Cipher::aes_\d+_ecb|Cipher::des_\w+|Cipher::rc4)/i }),
  // predictable randomness in a security context
  call({ ...CR, id: 'crypto-rng-js', langs: ['js'], need: 'always', what: 'uses a non-cryptographic random number generator for a security value', verify: rngVerify, sev: 'medium', title: 'Predictable random number generator',
    callee: x('Math\\.random'), args: 'any', allowNoArgs: true,
    fix: 'Use a cryptographically secure generator: crypto.randomBytes / crypto.randomUUID / crypto.getRandomValues (JS), secrets (Python), random_bytes (PHP), SecureRandom (Ruby/Java), crypto/rand (Go), RandomNumberGenerator (C#).' }),
  call({ ...CR, id: 'crypto-rng-py', langs: ['python'], need: 'always', what: 'uses a non-cryptographic random number generator for a security value', verify: rngVerify, title: 'Predictable random number generator',
    callee: x('random\\.(?:random|randint|choice|choices|randrange|getrandbits|sample|shuffle|randbytes|uniform)|(?:rng|rnd)\\.(?:random|randint|choice)'), args: 'any', allowNoArgs: true }),
  call({ ...CR, id: 'crypto-rng-php', langs: ['php'], need: 'always', what: 'uses a non-cryptographic random number generator for a security value', verify: rngVerify, title: 'Predictable random number generator',
    callee: x('rand|mt_rand|uniqid|lcg_value|shuffle|str_shuffle|array_rand|mt_srand|srand'), args: 'any', allowNoArgs: true }),
  call({ ...CR, id: 'crypto-rng-ruby', langs: ['ruby'], need: 'always', what: 'uses a non-cryptographic random number generator for a security value', verify: rngVerify, title: 'Predictable random number generator',
    callee: x('rand|Random\\.(?:rand|new|new_seed)|Kernel\\.rand|srand|(?:\\w+\\.)?(?:shuffle|sample)'), args: 'any', allowNoArgs: true, when: (c) => !/SecureRandom/.test(c.text) }),
  call({ ...CR, id: 'crypto-rng-go', langs: ['go'], need: 'always', what: 'uses math/rand (not cryptographically secure) for a security value', verify: rngVerify, title: 'Predictable random number generator',
    callee: x('\\w+\\.(?:Int|Intn|Int31|Int31n|Int63|Int63n|Uint32|Uint64|Float32|Float64|Seed|Read|Perm|Shuffle|New|NewSource|N|IntN|Uint32N|Uint64N|Int32|Int64|Int32N|Int64N)'), args: 'any', allowNoArgs: true,
    // The imports live in their own chunk, so the function chunk never contains `"crypto/rand"`. Flag only when the
    // qualifier is positively bound to math/rand in the file's import block (aliases included).
    when: (c, f) => goRandIsMath(fileText(f), c.callee.split('.')[0]) }),
  call({ ...CR, id: 'crypto-rng-jvm', langs: JVM, need: 'always', what: 'uses a non-cryptographic random number generator for a security value', verify: rngVerify, title: 'Predictable random number generator',
    callee: x('Math\\.random|(?:java\\.util\\.)?Random|ThreadLocalRandom\\.current|(?:\\w+\\.)?(?:nextInt|nextLong|nextBytes|nextDouble)'), args: 'any', allowNoArgs: true,
    when: (c, f) => (c.isNew && /Random$/.test(c.callee)) || /^Math\.random$|^ThreadLocalRandom/.test(c.callee) || (/\.(?:nextInt|nextLong|nextBytes|nextDouble)$/.test(c.callee) && !/SecureRandom/.test(f.ctx.literal) && /Random\b/.test(f.ctx.literal)) }),
  call({ ...CR, id: 'crypto-rng-csharp', langs: ['csharp'], need: 'always', what: 'uses System.Random (not cryptographically secure) for a security value', verify: rngVerify, title: 'Predictable random number generator',
    callee: x('Random|(?:\\w+\\.)?(?:Next|NextBytes|NextDouble|NextInt64)|Guid\\.NewGuid'), args: 'any', allowNoArgs: true,
    when: (c, f) => (c.callee === 'Random' && c.isNew) || (/\.(?:Next|NextBytes|NextDouble|NextInt64)$/.test(c.callee) && /\bRandom\b/.test(f.ctx.literal) && !/RandomNumberGenerator/.test(f.ctx.literal)) }),
  call({ ...CR, id: 'crypto-rng-dart', langs: ['dart'], need: 'always', what: 'uses a non-secure Random() for a security value', verify: rngVerify, title: 'Predictable random number generator',
    callee: x('Random'), args: 'any', allowNoArgs: true, when: (c) => !/\.secure$/.test(c.callee) && !/secure/.test(c.text) }),
  call({ ...CR, id: 'crypto-rng-c', langs: ['c'], need: 'always', what: 'uses a non-cryptographic random number generator for a security value', verify: rngVerify, title: 'Predictable random number generator',
    callee: x('rand|srand|random|srandom|drand48|lrand48|mrand48|erand48|rand_r|std::rand|std::srand|std::mt19937|mt19937'), args: 'any', allowNoArgs: true }),
  call({ ...CR, id: 'crypto-rng-swift', langs: ['swift'], need: 'always', what: 'uses a non-cryptographic random number generator for a security value', verify: rngVerify, title: 'Predictable random number generator',
    callee: x('rand|random|srand|srandom|drand48|arc4random_uniform_unsafe|GKRandomSource\\.sharedRandom|GKMersenneTwisterRandomSource|SystemRandomNumberGenerator_not'), args: 'any', allowNoArgs: true }),
  call({ ...CR, id: 'crypto-rng-rust', langs: ['rust'], need: 'always', what: 'uses a seedable non-cryptographic PRNG for a security value', verify: rngVerify, title: 'Predictable random number generator',
    callee: x('(?:SmallRng|StdRng|Pcg\\d+|XorShiftRng|XorShift\\w*|Lcg\\w*|SeedableRng)::(?:seed_from_u64|from_seed|from_entropy|new)|(?:fastrand|oorandom|nanorand)::\\w+'), args: 'any', allowNoArgs: true }),

  // TLS verification turned off
  pattern({ ...CR, id: 'crypto-tls-off', inString: true, langs: ['python', 'js', 'php', 'ruby', 'go', 'rust', 'java', 'kotlin', 'csharp', 'c'], sev: 'high', conf: 'high', title: 'TLS certificate validation disabled',
    re: /\bverify\s*=\s*False\b|\bssl\._create_unverified_context\b|\bssl\.CERT_NONE\b|\bcheck_hostname\s*=\s*False\b|\brejectUnauthorized\s*:\s*false\b|\bNODE_TLS_REJECT_UNAUTHORIZED\b[^\n]{0,20}['"]?0\b|\bstrictSSL\s*:\s*false\b|\bCURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0L?)\b|['"]verify['"]\s*=>\s*false|\bverify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE\b|\bssl_verify\s*[:=]\s*false\b|:verify_ssl\s*=>\s*false|\bInsecureSkipVerify\s*:\s*true\b|\bdanger_accept_invalid_(?:certs|hostnames)\s*\(\s*true\s*\)|\bNoopHostnameVerifier\b|\bALLOW_ALL_HOSTNAME_VERIFIER\b|\bTrustAllStrategy\b|\bTrustAllCerts?\b|\bX509TrustManager\b[^{]{0,200}\{\s*\}|\bServerCertificateValidationCallback\s*[+]?=\s*[^;\n]*(?:=>\s*true|delegate\s*\([^)]*\)\s*\{\s*return\s+true)|\bDangerousAcceptAnyServerCertificateValidator\b|\bSSL_VERIFY_NONE\b|\bsetHostnameVerifier\s*\(\s*(?:\([^)]*\)\s*->\s*true|new\s+HostnameVerifier\s*\(\s*\)\s*\{[^}]*return\s+true)|\bhostnameVerifier\s*\{\s*_\s*,\s*_\s*->\s*true\s*\}/,
    desc: 'TLS certificate / hostname verification is switched off, so a network attacker can impersonate the server and read or alter the traffic.',
    fix: 'Keep certificate and hostname verification enabled. To trust a private CA, add that CA to the trust store (or pin the certificate) instead of disabling checks.' }),
  // weak key sizes / KDF cost
  pattern({ ...CR, id: 'crypto-keysize', langs: CODE_FAMILIES, sev: 'high', title: 'Insufficient cryptographic key size',
    re: /\bmodulusLength\s*:\s*(?:512|768|1024)\b|\bRSA\.generate\s*\(\s*(?:512|768|1024)\b|\bGenerateKey\s*\([^,()]+,\s*(?:512|768|1024)\s*\)|\.initialize\s*\(\s*(?:512|768|1024)\s*\)|\bkey_?size\s*[=:]\s*(?:512|768|1024)\b|\bRSAKeyGenParameterSpec\s*\(\s*(?:512|768|1024)\b|\bRSA\.new\s*\(\s*(?:512|768|1024)\b|\bOpenSSL::PKey::RSA\.(?:new|generate)\s*\(\s*(?:512|768|1024)\b|\bRSA_generate_key(?:_ex)?\s*\([^,]*,\s*(?:512|768|1024)\b|\bbits\s*[:=]\s*(?:512|768|1024)\b|\bRsaPrivateKey::new\s*\([^,]+,\s*(?:512|768|1024)\b|\bRSACryptoServiceProvider\s*\(\s*(?:512|768|1024)\s*\)|\bgenerateKeyPair\s*\(\s*['"]rsa['"]\s*,\s*\{[^}]*modulusLength\s*:\s*(?:512|768|1024)/,
    desc: 'An RSA key of 1024 bits or fewer is used; keys of this size can be factored with modest resources.', fix: 'Use RSA keys of at least 2048 bits (3072 recommended) or an elliptic-curve key (P-256 / Ed25519).' }),
  pattern({ ...CR, id: 'crypto-kdf-cost', langs: CODE_FAMILIES, sev: 'medium', title: 'Key-derivation cost too low',
    re: /\b(?:iterations?|iter|rounds|PBKDF2_ITERATIONS)\s*[=:]\s*(\d{1,4})\b(?![.\d])/i, check: (mm, flow, text) => { const n = +mm[1]; const near = text.slice(Math.max(0, mm.index - 200), mm.index + 200); return n < 10000 && /pbkdf2|kdf|derive|scrypt|bcrypt|argon|password|passphrase/i.test(near) && !/\b(?:test|mock)\b/i.test(flow.chunk.file || ''); },
    desc: 'The key-derivation function runs with fewer than 10,000 iterations, which makes password guessing cheap.', fix: 'Use Argon2id, scrypt or bcrypt, or PBKDF2-HMAC-SHA256 with at least 600,000 iterations.' }),
  // fixed IV / nonce / salt
  pattern({ ...CR, id: 'crypto-static-iv', inString: true, langs: CODE_FAMILIES, sev: 'medium', title: 'Hardcoded initialization vector / nonce / salt',
    re: /\b(?:iv|IV|initVector|init_vector|initialization_?vector|nonce|NONCE|salt|SALT)\w*\s*(?::=|=|:)\s*(?:b|u|r)?["'`][^"'`\n]{8,}["'`]/, check: (mm) => !/(?:process\.env|os\.environ|getenv|config|settings)\b/.test(mm[0]) && !/^(?:\w+\s*[:=]\s*)?["'`](?:\$\{|%\(|\{\{|<)/.test(mm[0]),
    desc: 'A fixed initialization vector / nonce / salt is hardcoded. Reusing it across encryptions breaks the security of CBC/CTR/GCM and defeats salting.', fix: 'Generate a fresh random IV/nonce (and a per-password salt) with a CSPRNG for every encryption/hash, and store it next to the ciphertext.' }),
];

// ═══ JWT / token validation weakness ═════════════════════════════════════════
const JW = { cls: 'JWT / token validation weakness', sev: 'high', conf: 'high', group: 'jwt' };
const JWT_RULES = [
  pattern({ ...JW, id: 'jwt-weak', inString: true, langs: CODE_FAMILIES, title: 'JWT signature or claim validation disabled',
    re: /\bjwt\.decode\s*\([^)]*\bverify\s*=\s*False\b|["']verify_signature["']\s*:\s*False|["']verify_(?:exp|aud|iss|nbf)["']\s*:\s*False|\balgorithms?\s*[=:]\s*\[?\s*["']none["']|\balgorithm\s*[:=]\s*["']none["']|\bignoreExpiration\s*:\s*true\b|\bJWT\.decode\s*\([^)]*(?:nil|null)\s*,\s*false\b|\bJWT::decode\s*\([^)]*\[\s*["']none["']\s*\]|\bSigningMethodNone\b|\bUnsafeAllowNoneSignatureType\b|\bParseUnverified\b|\bSignatureAlgorithm\.NONE\b|\bAlgorithm\.none\s*\(\s*\)|\bValidateIssuerSigningKey\s*=\s*false\b|\bRequireSignedTokens\s*=\s*false\b|\bValidateLifetime\s*=\s*false\b|\bSignatureValidator\s*=\s*\([^)]*\)\s*=>|\binsecure_disable_signature_validation\b|\bdangerous_insecure_decode\b|\bvalidate_exp\s*=\s*false\b|\bRequireExpirationTime\s*=\s*false\b|\bValidateAudience\s*=\s*false\b|\bValidateIssuer\s*=\s*false\b/,
    desc: 'JSON Web Token signature or claim validation is disabled or set to the "none" algorithm, so an attacker can forge tokens or replay expired ones.',
    fix: 'Always verify the signature with a fixed, server-chosen algorithm and key; reject alg "none"; validate exp, nbf, iss and aud.' }),
  call({ ...JW, id: 'jwt-decode-only', langs: ['js', 'java', 'kotlin', 'csharp', 'dart'], need: 'always', conf: 'low', sev: 'medium', title: 'JWT decoded without signature verification', what: 'decodes a JWT without verifying its signature', args: 'any',
    callee: x('(?:jwt|jsonwebtoken|jwtDecode|jwt_decode|JwtDecoder|JWT)\\.decode|jwtDecode|jwt_decode|JwtSecurityTokenHandler\\(\\)\\.ReadJwtToken|(?:\\w+\\.)?ReadJwtToken|JwtDecoder\\.decode'),
    verify: (c, flow) => (/(?:jwt|jsonwebtoken)\.verify|\.verify\s*\(|ValidateToken|parseClaimsJws|JWTVerifier|require\(\s*["']jsonwebtoken|verifySignature/.test(flow.ctx.literal) ? { valid: false, reason: 'the token is also verified (signature checked) in the same code' } : null) }),
  call({ ...JW, id: 'jwt-hardcoded-key', langs: ['js', 'python', 'php', 'ruby', 'go', 'java', 'kotlin', 'csharp', 'rust'], need: 'always', sev: 'high', title: 'Hardcoded JWT signing key', what: 'signs or verifies a JWT with a key embedded in the source', args: 'any',
    callee: x('(?:jwt|jsonwebtoken)\\.(?:sign|verify)|jwt\\.encode|jwt\\.decode|JWT::(?:encode|decode)|JWT\\.(?:encode|decode)|(?:\\w+\\.)?SignedString|(?:\\w+\\.)?setSigningKey|Algorithm\\.HMAC(?:256|384|512)|Keys\\.hmacShaKeyFor|SymmetricSecurityKey|EncodingKey::from_secret|DecodingKey::from_secret|(?:Jwts\\.builder\\(\\)\\.)?signWith'),
    when: (c) => { const a = c.callee === 'jwt.decode' || /verify$|decode$/.test(c.callee) ? c.args[1] : c.callee.endsWith('sign') || /encode$/.test(c.callee) ? c.args[1] : c.args[0]; const lit = (a?.lit || '').trim(); return /^(?:b|u|r)?["'`][^"'`\n]{3,}["'`]$/.test(lit) || /^\[\]byte\(\s*["'`][^"'`\n]{3,}["'`]\s*\)$/.test(lit) || /^(?:Encoding\.\w+\.GetBytes|"[^"]+"\.toByteArray|"[^"]+"\.getBytes|b"[^"]+"|"[^"]+"\.as_bytes\(\))/.test(lit) || /["'`][^"'`\n]{8,}["'`]/.test(lit) && /(?:getBytes|GetBytes|toByteArray|as_bytes|\[\]byte)/.test(lit); },
    desc: 'The JWT signing/verification key is a string literal in the source, so anyone who can read the code can mint valid tokens.', fix: 'Load the signing key from a secret store or environment variable and rotate it; prefer asymmetric keys (RS256/ES256) for tokens verified by other services.' }),
];

// ═══ Insecure session cookie attributes ═════════════════════════════════════
const CK = { cls: 'insecure session cookie attributes', sev: 'medium', conf: 'medium', group: 'cookie' };
const COOKIE_RULES = [
  pattern({ ...CK, id: 'cookie-explicit-off', inString: true, langs: WEB, title: 'Cookie security attribute explicitly disabled',
    re: /\b(?:httpOnly|HttpOnly|http_only|httponly|secure|Secure|SESSION_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|CSRF_COOKIE_SECURE|CSRF_COOKIE_HTTPONLY|cookie_secure|cookie_httponly)\s*(?:[:=]|=>|,)\s*(?:false|False|0|FALSE)\b|\bsetHttpOnly\s*\(\s*false\s*\)|\bsetSecure\s*\(\s*false\s*\)|\.(?:secure|http_only)\s*\(\s*false\s*\)|\bCookieSecurePolicy\.None\b|\bSameSite\s*[=:]\s*(?:SameSiteMode\.None|["']none["']|None|:none)\b|\bsameSite\s*:\s*["']?none["']?|\bsession\.cookie_(?:secure|httponly)['"]?\s*,\s*['"]?(?:0|Off|false)|SESSION_COOKIE_SAMESITE\s*=\s*None/i,
    check: (mm, flow, text) => /cookie|session|csrf|Cookie|Session/.test(text.slice(Math.max(0, mm.index - 300), mm.index + 200)),
    desc: 'A session/CSRF cookie is configured without HttpOnly or Secure (or with SameSite=None), exposing it to script access and to interception over plain HTTP.',
    fix: 'Set HttpOnly, Secure and SameSite=Lax (or Strict) on session cookies.' }),
  call({ ...CK, id: 'cookie-js-default', langs: ['js'], need: 'always', title: 'Cookie set without HttpOnly/Secure attributes', what: 'sets a cookie without HttpOnly / Secure options', conf: 'low', args: 'any', chain: true,
    callee: /^(?:res|response|reply|ctx\.cookies|resp)(?:\.\w+\(\))*\.(?:cookie|setCookie|set)$/, when: (c) => /\.cookie$|\.setCookie$|cookies\.set$/.test(c.callee) && c.args.length >= 2 && !/httpOnly/i.test(c.text) && SEC_WORDS.test(c.args[0]?.lit || '') }),
  call({ ...CK, id: 'cookie-py-default', langs: ['python'], need: 'always', title: 'Cookie set without HttpOnly/Secure attributes', what: 'sets a cookie without HttpOnly / Secure', conf: 'low', args: 'any',
    callee: m('set_cookie|set_signed_cookie'), when: (c) => !(/secure\s*=\s*True/.test(c.text) && /httponly\s*=\s*True/i.test(c.text)) && SEC_WORDS.test(c.args[0]?.lit || '') }),
  call({ ...CK, id: 'cookie-php-default', langs: ['php'], need: 'always', title: 'Cookie set without HttpOnly/Secure attributes', what: 'sets a cookie without HttpOnly / Secure', conf: 'low', args: 'any',
    callee: x('setcookie|setrawcookie'), when: (c) => c.args.length >= 2 && !/httponly/i.test(c.lit) && !(c.args.length >= 7 && /true/i.test(c.args[5]?.lit || '') && /true/i.test(c.args[6]?.lit || '')) && SEC_WORDS.test(c.args[0]?.lit || '') }),
  custom({ ...CK, id: 'cookie-go-struct', langs: ['go'], title: 'Cookie set without HttpOnly/Secure attributes', conf: 'medium',
    run(flow, emit) {
      const lit = flow.ctx.literal;
      const re = /&?http\.Cookie\s*\{/g; let mm;
      while ((mm = re.exec(lit)) !== null) {
        let depth = 1, i = mm.index + mm[0].length;                      // balanced-brace body (nested literals inside)
        for (; i < lit.length && depth > 0; i++) { if (lit[i] === '{') depth++; else if (lit[i] === '}') depth--; }
        const body = lit.slice(mm.index + mm[0].length, i - 1);
        if (!/Name\s*:/.test(body)) continue;
        if (/MaxAge\s*:\s*-\s*1\b/.test(body)) continue;                // deleting a cookie
        // `Secure: cfg.CookieSecure` is configurable, not missing: only a missing field or a literal false is flagged
        const on = (attr) => new RegExp(attr + '\\s*:\\s*(?!false\\b)\\S').test(body);
        const missing = [!on('HttpOnly') && 'HttpOnly', !on('Secure') && 'Secure'].filter(Boolean);
        if (missing.length && SEC_WORDS.test(body)) emit(mm.index, { desc: `A cookie is created without ${missing.join(' and ')} set to true.`, fix: 'Set HttpOnly: true, Secure: true and SameSite: http.SameSiteLaxMode.' });
      }
    } }),
  custom({ ...CK, id: 'cookie-jvm-new', langs: JVM, title: 'Cookie set without HttpOnly/Secure attributes', conf: 'low',
    run(flow, emit) {
      const re = /\bnew\s+Cookie\s*\(/g; let mm;
      while ((mm = re.exec(flow.ctx.code)) !== null) {
        const stmt = flow.chunk.code.slice(mm.index, mm.index + 600);
        if (!/setHttpOnly\s*\(\s*true|setSecure\s*\(\s*true/.test(flow.ctx.literal) && SEC_WORDS.test(flow.ctx.literal.slice(mm.index, mm.index + 80))) emit(mm.index, { desc: 'A cookie is created without setHttpOnly(true) / setSecure(true).' });
      }
    } }),
  pattern({ ...CK, id: 'cookie-session-config', langs: ['js'], title: 'Session cookie configured without secure attributes', conf: 'low',
    re: /\bsession\s*\(\s*\{[^}]*\}\s*\)/, check: (mm) => !/cookie\s*:\s*\{[^}]*(?:httpOnly\s*:\s*true)/.test(mm[0]) || !/secure\s*:\s*(?:true|process)/.test(mm[0]),
    desc: 'express-session is configured without cookie.httpOnly and cookie.secure set to true.', fix: 'Pass cookie: { httpOnly: true, secure: true, sameSite: "lax" } to session().' }),
];

// ═══ Insecure CORS ═══════════════════════════════════════════════════════════
const CORS = { cls: 'insecure CORS policy', sev: 'medium', conf: 'high', group: 'cors' };
const CORS_RULES = [
  pattern({ ...CORS, id: 'cors-wildcard', inString: true, langs: WEB, title: 'Overly permissive CORS policy',
    re: /\borigin\s*:\s*(?:["']\*["']|true)\b|Access-Control-Allow-Origin["']?\s*[,:=]\s*["']?\s*\*|\bCORS_ORIGIN_ALLOW_ALL\s*=\s*True\b|\bCORS_ALLOW_ALL_ORIGINS\s*=\s*True\b|\ballow_origins\s*=\s*\[\s*["']\*["']\s*\]|\ballow_origin_regex\s*=\s*["']\.\*["']|\borigins\s+["']\*["']|\bAllowAllOrigins\s*:\s*true\b|\bAllowOrigins\s*:\s*\[\]string\s*\{\s*"\*"|\bAllowedOrigins\s*:\s*\[\]string\s*\{\s*"\*"|\ballow_any_origin\s*\(\s*\)|\b(?:Cors|CorsLayer)::(?:permissive|very_permissive)\s*\(\s*\)|\bAllowOrigin::(?:any|mirror_request)\s*\(\s*\)|@CrossOrigin\s*\(\s*(?:origins\s*=\s*)?["']\*["']|\ballowedOrigins\s*\(\s*["']\*["']|\ballowedOriginPatterns\s*\(\s*["']\*["']|\bAllowAnyOrigin\s*\(\s*\)|\bWithOrigins\s*\(\s*["']\*["']\s*\)|\bSetIsOriginAllowed\s*\([^)]*=>\s*true\s*\)|\banyHost\s*\(\s*\)|\ballowHost\s*\(\s*["']\*["']|header\s*\(\s*["']Access-Control-Allow-Origin:\s*\*/,
    desc: 'The CORS policy allows any origin. If credentials or sensitive responses are involved, any website can read them in a visitor\'s browser.',
    fix: 'Allow only an explicit list of trusted origins; never combine a wildcard / reflected origin with credentials.' }),
  pattern({ ...CORS, id: 'cors-reflect', inString: true, langs: ['js', 'php', 'python', 'ruby', 'go', 'java', 'kotlin', 'csharp'], sev: 'high', title: 'CORS origin reflected from the request',
    re: /Access-Control-Allow-Origin["']?\s*[,:=]\s*(?:req(?:uest)?\.(?:headers\.origin|headers\[["']origin["']\]|get\(\s*["']origin["']\s*\)|header\(\s*["']origin["']\s*\))|\$_SERVER\s*\[\s*["']HTTP_ORIGIN["']\s*\]|request\.headers(?:\.get\(|\[)\s*["']Origin["']|r\.Header\.Get\(\s*["']Origin["']\s*\)|request\.getHeader\(\s*["']Origin["']\s*\)|Request\.Headers\s*\[\s*["']Origin["']\s*\])|["']Access-Control-Allow-Origin:\s*["']\s*\.\s*\$_SERVER\s*\[\s*["']HTTP_ORIGIN["']/,
    desc: 'The Access-Control-Allow-Origin header is set from the request\'s Origin header, which allows every origin (including with credentials).', fix: 'Compare the Origin against an allowlist and echo it only when it matches.' }),
  pattern({ ...CORS, id: 'cors-default', langs: ['js', 'python'], conf: 'low', sev: 'low', title: 'CORS enabled with default (allow-all) settings',
    re: /\bapp\.use\s*\(\s*cors\s*\(\s*\)\s*\)|\bCORS\s*\(\s*(?:app|application)\s*\)/,
    desc: 'CORS is enabled with the library default, which allows every origin.', fix: 'Configure an explicit origin allowlist.' }),
];

// ═══ Debug / verbose error mode ══════════════════════════════════════════════
const DBG = { cls: 'debug / verbose error mode enabled in production', sev: 'medium', conf: 'high', group: 'debug' };
const DEBUG_RULES = [
  pattern({ ...DBG, id: 'debug-on', langs: WEB, title: 'Debug mode enabled',
    re: /\bapp\.run\s*\([^)]*\bdebug\s*=\s*True\b|\bapp\.debug\s*=\s*True\b|^\s*DEBUG\s*=\s*True\b|\bFLASK_DEBUG\s*[=:]\s*["']?(?:1|true)|\buse_debugger\s*=\s*True\b|\buvicorn\.run\s*\([^)]*\bdebug\s*=\s*True|\bdisplay_errors["']?\s*[=,]\s*["']?(?:1|On|true)\b|\bini_set\s*\(\s*["']display_errors["']\s*,\s*["']?(?:1|On|true)|\bAPP_DEBUG\s*=\s*true\b|\bphpinfo\s*\(\s*\)|\bconfig\.consider_all_requests_local\s*=\s*true\b|\bconfig\.action_dispatch\.show_exceptions\s*=\s*true\b|\bset\s+:show_exceptions\s*,\s*true\b|\bset\s+:raise_errors\s*,\s*true\b|\bgin\.SetMode\s*\(\s*gin\.DebugMode\s*\)|\bUseDeveloperExceptionPage\s*\(\s*\)|\bIncludeErrorDetailPolicy\s*=\s*[\w.]*Always\b|\bspring\.devtools\.restart\.enabled\s*=\s*true|\bserver\.error\.include-(?:stacktrace|message)\s*=\s*always|\berrorhandler\s*\(\s*\)|\bapp\.use\s*\(\s*errorhandler|\bdebug\s*:\s*true\b(?=[^\n]*(?:app|server|express|koa|fastify|graphql|apollo))/m,
    check: (mm, flow, text) => {
      if (/UseDeveloperExceptionPage/.test(mm[0])) { const near = text.slice(Math.max(0, mm.index - 250), mm.index); return !/IsDevelopment|IsEnvironment\s*\(\s*["']Development|env\.|Environment/.test(near); }
      if (/^\s*DEBUG\s*=\s*True/.test(mm[0]) || /DebugMode/.test(mm[0]) || /display_errors/.test(mm[0])) return !/(?:dev|local|test|example|sample)/i.test(flow.chunk.file || '') && !/\b(?:if|elif)\b[^\n]{0,80}(?:dev|debug|local)/i.test(text.slice(Math.max(0, mm.index - 200), mm.index));
      return true;
    },
    desc: 'The application is configured to run in debug / verbose-error mode, which exposes stack traces, source paths and (for some frameworks) an interactive console.',
    fix: 'Disable debug mode outside local development; drive it from the environment (e.g. DEBUG=False in production) and return generic error pages.' }),
];

const DEBUG_WP = pattern({ ...DBG, id: 'debug-wp', inString: true, langs: ['php'], title: 'Debug mode enabled', re: /\bdefine\s*\(\s*["']WP_DEBUG["']\s*,\s*true\s*\)/,
  desc: 'WordPress WP_DEBUG is enabled, which prints PHP errors and notices to visitors.', fix: 'Set WP_DEBUG to false (and WP_DEBUG_DISPLAY to false) outside development.' });
DEBUG_RULES.push(DEBUG_WP);

// ═══ Sensitive data exposure ═════════════════════════════════════════════════
const SD = { cls: 'sensitive data exposure / information disclosure', sev: 'medium', conf: 'medium', group: 'exposure' };
const SENSITIVE_ID = /(?:password|passwd|passphrase|\bpwd\b|secret|api_?key|access_?token|refresh_?token|auth_?token|bearer|authorization|credit_?card|card_?number|\bcvv\b|\bssn\b|private_?key)/i;
const SENSITIVE_DATA_RULES = [
  pattern({ ...SD, id: 'exposure-stack', langs: WEB, title: 'Stack trace / internal error details returned to the client',
    re: /\b(?:res|response|reply|resp|ctx)(?:\.\w+\([^()]*\))*\.(?:send|json|end|write|body)\s*\(\s*(?:\{[^}]*)?\b(?:err|error|e|ex)\.stack\b|\bres\.(?:send|json)\s*\(\s*(?:err|error|e)\s*\)|\b(?:return|jsonify|HttpResponse|Response|JsonResponse|make_response|echo|print)\b[^\n]{0,80}(?:traceback\.format_exc\s*\(|traceback\.print_exc|\$e\s*->\s*getTraceAsString\s*\(|\$e\s*->\s*getTrace\s*\(|print_r\s*\(\s*\$e\b)|\brender\b[^\n]{0,60}\b(?:e|ex|error|exception)\.(?:backtrace|message)|\bprintStackTrace\s*\(\s*(?:response|resp|res)\s*\.\s*getWriter|\b(?:Response|HttpContext\.Response)\.Write\s*\(\s*(?:ex|e|exception)\s*(?:\.\s*(?:ToString|StackTrace)\s*\(\s*\)?)?\s*\)|\breturn\b[^\n]{0,40}\b(?:ex|e|exception)\.(?:ToString\s*\(\s*\)|StackTrace)\b|\bhttp\.Error\s*\(\s*w\s*,\s*(?:err|e)\.Error\s*\(\s*\)|\bdebug\.Stack\s*\(\s*\)|\bfmt\.Fprint(?:f|ln)?\s*\(\s*w\s*,[^)]*(?:err|debug\.Stack)/,
    desc: 'Internal error details (stack trace / exception text) are returned to the client, leaking file paths, library versions and logic to an attacker.',
    fix: 'Log the exception server-side and return a generic error message with a correlation id.' }),
  call({ ...SD, id: 'exposure-log-secret', langs: ['js', 'python', 'ruby', 'java', 'kotlin', 'csharp', 'go', 'php', 'dart', 'swift', 'rust'], need: 'always', title: 'Sensitive value written to logs', what: 'writes a credential or personal data value to a log', args: 'any',
    callee: /^(?:logger|log|LOG|LOGGER|_logger|_log|Log|Logger|logging|console|app\.logger|Rails\.logger|self\.logger|this\.logger|slog|syslog|NSLog|os_log|debugPrint|print|println|error_log|(?:log|tracing)::\w+!|(?:info|warn|error|debug|trace)!|\$this\.logger|\$logger|\$log)(?:\.(?:info|debug|warn|warning|error|critical|fatal|trace|log|notice|exception|Info|Debug|Warn|Error|Print|Printf|Println|Fatal|Infof|Debugf|Errorf|Warnf|LogInformation|LogDebug|LogError|LogWarning|d|i|w|e|v))?$/,
    when: (c) => c.args.some(a => { const t = a.text.replace(/\bpassword[_-]?(?:reset|changed|policy|field|label|hint|error|valid\w*)\b/gi, ''); return SENSITIVE_ID.test(t) && !/["'`]\s*$/.test(t) && /[A-Za-z_]/.test(t); }),
    verify: (cand) => { const a = cand.call.args.find(a => SENSITIVE_ID.test(a.text)); return a && /^["'`][^"'`]*["'`]$/.test(a.lit.trim()) ? { valid: false, reason: 'only a literal message mentions the word, no value is logged' } : null; },
    desc: 'A variable that holds a credential, token or personal data is written to the application log, where it persists in plain text and is readable by anyone with log access.', fix: 'Never log secrets or personal data; log an identifier or a masked value instead.' }),
];

// ═══ Insecure file permissions ═══════════════════════════════════════════════
const FP = { cls: 'insecure file permissions (world‑writable or executable)', sev: 'medium', conf: 'medium', group: 'perm' };
const PERM_RULES = [
  pattern({ ...FP, id: 'perm-world-writable', langs: ALLL, title: 'World-writable file permissions',
    re: /\b(?:chmod|chmodSync|fchmod|lchmod|mkdir|mkdirSync|mkdirs|makedirs|mkdir_p|MkdirAll|Mkdir|umask|WriteFile|OpenFile|set_mode|setPermissions|set_permissions|createFile|creat|open|mode|permissions|NSFilePosixPermissions|FileMode|FilePermissions|Chmod|Perm|perm)\b[^;\n]{0,90}?(?<![\w.])(0o?[0-7]{3,4})(?![\w.])|\bchmod\s+(?:-R\s+)?(?:a\+[rwx]*w|o\+[rwx]*w|ugo\+[rwx]*w|go\+[rwx]*w|[0-7]?[0-7][0-7][2367])\b|\bumask\s*\(\s*0+\s*\)|["']rw[xs-]rw[xs-]rw[xt-]["']|["']rw-rw-rw-["']|\bsetWritable\s*\(\s*true\s*,\s*false\s*\)|\bFileSystemRights\.FullControl\b[^;\n]*Everyone|\bS_IRWXO\b|\bS_IWOTH\b|\bPosixFilePermission\.OTHERS_WRITE\b/,
    check: (mm, flow, text) => { if (mm[1]) { const at = mm.index + mm[0].lastIndexOf(mm[1]); if (/(?:&|~|\||==|===|!=|!==|>=|<=|>|<)\s*$/.test(text.slice(Math.max(0, at - 6), at))) return false; const n = parseInt(mm[1].replace(/^0o?/, '') || '0', 8); return (n & 0o002) !== 0 && n !== 0; } return true; },
    desc: 'A file or directory is created/changed with permissions that let every local user write to it, enabling tampering and privilege escalation.', fix: 'Use the least permissive mode that works (0600 for files, 0700 for directories, 0640/0750 when a group needs access) and set umask 027 or stricter.' }),
];

// ═══ CSRF ════════════════════════════════════════════════════════════════════
const CS = { cls: 'cross-site request forgery (CSRF)', sev: 'medium', conf: 'high', group: 'csrf' };
const CSRF_RULES = [
  pattern({ ...CS, id: 'csrf-disabled', langs: WEB, title: 'CSRF protection disabled',
    re: /\bcsrf\s*\(\s*\)\s*\.\s*disable\s*\(\s*\)|\bcsrf\s*\(\s*(?:\w+\s*->\s*\w+\s*\.\s*disable\s*\(\s*\)|AbstractHttpConfigurer\s*::\s*disable|\w+\s*->\s*\w+\.disable\(\))\s*\)|\bcsrf\s*\{\s*disable\s*\(\s*\)\s*\}|\bcsrf\.disable\s*\(\s*\)|@csrf_exempt\b|\bcsrf\.exempt\b|\bWTF_CSRF_ENABLED["']?\s*\]?\s*=\s*False\b|\bWTF_CSRF_CHECK_DEFAULT["']?\s*\]?\s*=\s*False\b|\$except\s*=\s*\[[^\]]*["']\*["']|\bskip_before_action\s+:verify_authenticity_token\b|\bskip_forgery_protection\b|\ballow_forgery_protection\s*=\s*false\b|\[\s*IgnoreAntiforgeryToken\s*\]|\bIgnoreAntiforgeryTokenAttribute\b|\bcsrf\s*:\s*false\b|\bcsrfProtection\s*:\s*false\b|\bCsrfViewMiddleware\b[^\n]*#\s*disabled/,
    check: (mm, flow) => !/(?:api|webhook|hook|callback|stripe|github|slack|twilio)/i.test(flow.chunk.name || '') || /disable\s*\(\s*\)/.test(mm[0]),
    desc: 'CSRF protection is switched off (or a handler is exempted), so a malicious page can make a logged-in user\'s browser submit state-changing requests.',
    fix: 'Keep CSRF protection enabled for cookie-authenticated endpoints; exempt only token-authenticated machine endpoints (webhooks) and verify their signature instead.' }),
];

// ═══ Missing / misconfigured security headers ═══════════════════════════════
const SH = { cls: 'missing / misconfigured security headers', sev: 'low', conf: 'high', group: 'headers' };
const HEADER_CFG_RULES = [
  pattern({ ...SH, id: 'headers-weak', inString: true, langs: WEB, title: 'Security header disabled or weakened',
    re: /X-Frame-Options["']?\s*[,:=]\s*["']?\s*ALLOW(?:ALL|-FROM)?\b|\bX_FRAME_OPTIONS\s*=\s*["']ALLOWALL|\bhelmet\s*\(\s*\{[^}]*\b(?:contentSecurityPolicy|frameguard|hsts|xssFilter|noSniff|crossOriginEmbedderPolicy|referrerPolicy)\s*:\s*false|\bcontentSecurityPolicy\s*:\s*false\b|Content-Security-Policy["']?\s*[,:=]\s*["'][^"'\n]*(?:'unsafe-inline'|'unsafe-eval'|\bdefault-src\s+\*|\bscript-src\s+(?:[^;"']*\s)?\*)|\bSECURE_HSTS_SECONDS\s*=\s*0\b|\bSECURE_SSL_REDIRECT\s*=\s*False\b|\bSECURE_CONTENT_TYPE_NOSNIFF\s*=\s*False\b|\bSECURE_BROWSER_XSS_FILTER\s*=\s*False\b|\bconfig\.force_ssl\s*=\s*false\b|\bframeOptions\s*\(\s*\)\s*\.\s*disable\s*\(\s*\)|\bframeOptions\.disable\s*\(\s*\)|\bcontentTypeOptions\s*\(\s*\)\s*\.\s*disable|\bhttpStrictTransportSecurity\s*\(\s*\)\s*\.\s*disable|\bxssProtection\s*\(\s*\)\s*\.\s*disable|\bheaders\s*\(\s*\)\s*\.\s*disable\s*\(\s*\)|\bheaders\s*\{\s*disable\s*\(\s*\)\s*\}|\bheaders\.disable\s*\(\s*\)/,
    desc: 'A browser security header (CSP, X-Frame-Options, HSTS, nosniff) is disabled or set to a permissive value, removing a layer of defence against clickjacking, XSS and downgrade attacks.',
    fix: 'Enable the headers with restrictive values (CSP without unsafe-inline/unsafe-eval, X-Frame-Options: DENY or frame-ancestors, HSTS with includeSubDomains).' }),
];

export const SECRETS_CRYPTO_RULES = [
  ...SECRET_RULES, ...CRYPTO_RULES, ...JWT_RULES, ...COOKIE_RULES, ...CORS_RULES, ...DEBUG_RULES,
  ...SENSITIVE_DATA_RULES, ...PERM_RULES, ...CSRF_RULES, ...HEADER_CFG_RULES,
];
