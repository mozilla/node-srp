

const crypto = require('crypto'),
      bigint = require('bigint'),
      Put = require('put');

/*
 * If a conversion is explicitly specified with the operator PAD(),
 * the integer will first be implicitly converted, then the resultant
 * byte-string will be left-padded with zeros (if necessary) until its
 * length equals the implicitly-converted length of N.
 *
 * params:
 *         n (bigint)       Number to pad
 *         N (bigint)       N
 *
 * returns: buffer
 */
var pad = exports.pad = function pad(n, N) {
  var padding = N.bitLength() - n.bitLength();
  console.log(padding);
  if (padding <= 0) {
    return n.toBuffer();
  }
  var buf = Put()
      .pad(padding)
      .put(n.toBuffer())
      .buffer();
  return buf;
};

/*
 * The verifier is calculated as described in Section 3 of [SRP-RFC].
 * We give the algorithm here for convenience.
 *
 * The verifier (v) is computed based on the salt (s), user name (I),
 * password (P), and group parameters (N, g).  The computation uses the
 * [SHA1] hash algorithm:
 *
 *         x = SHA1(s | SHA1(I | ":" | P))
 *         v = g^x % N
 *
 * params:
 *         s (bigint)       salt
 *         I (string)       user identity
 *         P (string)       user password
 *         N (bigint)       group parameter N
 *         g (bigint)       generator
 *         alg (string)     default = 'sha256'
 *
 * returns: bigint
 */
var getV = exports.getV = function getV(s, I, P, N, g, alg) {
  alg = alg || 'sha256';
  var hashIP = crypto.createHash(alg).update(I + ':' + P).digest('binary');
  var hashX = crypto.createHash(alg).update(s.toBuffer()).update(hashIP).digest('hex');
  var x = bigint(hashX, 16);

  return g.powm(x, N);
};

/*
 * calculate the SRP-6 multiplier
 *
 * params:
 *         N (bigint)       group parameter N
 *         g (bigint)       generator
 *         alg (string)     default = 'sha256'
 *
 * returns: bigint
 */
var getk = exports.getk = function getk(N, g, alg) {
  alg = alg || 'sha256';
  var PADg = pad(g, N);
  return bigint(crypto.createHash(alg).update(N.toBuffer()).update(PADg).digest('hex'), 16);
};

/*
 * The server key exchange message contains the prime (N), the generator
 * (g), and the salt value (s) read from the SRP password file based on
 * the user name (I) received in the client hello extension.
 *
 * The server key exchange message also contains the server's public
 * value (B).  The server calculates this value as B = k*v + g^b % N,
 * where b is a random number that SHOULD be at least 256 bits in length
 * and k = SHA1(N | PAD(g)).
 *
 * params:
 *         v (bigint)       verifier
 *         g (bigint)       generator
 */
var getB = exports.getB = function getB(v, g, b, N, alg) {
  alg = alg || 'sha256';
  var k = getk(N, g, alg);
  return k.mul(v).add(g.powm(b, N));
};