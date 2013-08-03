const crypto = require('crypto'),
      bignum = require('bignum'),
      assert = require('assert'),
      ALG = 'sha256';

/*
 * If a conversion is explicitly specified with the operator PAD(),
 * the integer will first be implicitly converted, then the resultant
 * byte-string will be left-padded with zeros (if necessary) until its
 * length equals the implicitly-converted length of N.
 *
 * params:
 *         n (bignum)       Number to pad
 *         N (bignum)       N
 *
 * returns: buffer
 */
var pad = exports.pad = function pad(n, N) {
  // a Put padding is specified in bytes
  var N_bytes = Math.ceil(N.bitLength() / 8);
  var n_bytes = Math.ceil(n.bitLength() / 8);
  var padding = N_bytes - n_bytes;
  if (padding < 0) {
    throw("Negative padding.  Very uncomfortable.");
  }
  var b = n.toBuffer();
  var result = new Buffer(padding + b.length);
  result.fill(0, 0, padding);
  b.copy(result, padding);
  return result;
};

/*
 * compute the intermediate value x as a hash of three buffers:
 * salt, identity, and password.  And a colon.  FOUR buffers.
 *
 *      x = H(s | H(I | ":" | P))
 *
 * params:
 *         s (buffer)       salt
 *         I (buffer)       user identity
 *         P (buffer)       user password
 */
var getx = exports.getx = function getx(s, I, P, alg) {
  assert(Buffer.isBuffer(s), "Type error: salt (s) must be a buffer");
  assert(Buffer.isBuffer(I), "Type error: identity (I) must be a buffer");
  assert(Buffer.isBuffer(P), "Type error: password (P) must be a buffer");
  alg = alg || ALG;
  var hashIP = crypto.createHash(alg)
    .update(Buffer.concat([I, new Buffer(':'), P]))
    .digest('binary');
  var hashX = crypto.createHash(alg)
    .update(s)
    .update(hashIP)
    .digest('hex');
  return bignum(hashX, 16);
};

/*
 * The verifier is calculated as described in Section 3 of [SRP-RFC].
 * We give the algorithm here for convenience.
 *
 * The verifier (v) is computed based on the salt (s), user name (I),
 * password (P), and group parameters (N, g).
 *
 *         x = H(s | H(I | ":" | P))
 *         v = g^x % N
 *
 * params:
 *         s (buffer)       salt
 *         I (buffer)       user identity
 *         P (buffer)       user password
 *         N (bignum)       group parameter N
 *         g (bignum)       generator
 *         alg (string)     default = ALG
 *
 * returns: bignum
 */
var getv = exports.getv = function getv(s, I, P, N, g, alg) {
  alg = alg || ALG;
  return g.powm(getx(s, I, P, alg), N);
};

/*
 * calculate the SRP-6 multiplier
 *
 * params:
 *         N (bignum)       group parameter N
 *         g (bignum)       generator
 *         alg (string)     default = ALG
 *
 * returns: bignum
 */
var getk = exports.getk = function getk(N, g, alg) {
  alg = alg || ALG;
  return bignum(
    crypto
      .createHash(alg)
      .update(N.toBuffer())
      .update(pad(g, N))
      .digest('hex'), 16);
};

/*
 * Generate a random key
 *
 * params:
 *         bytes (int)      length of key (default=32)
 *         callback (func)  function to call with err,key
 *
 * returns: bignum
 */
var genKey = exports.genKey = function genKey(bytes, callback) {
  // bytes is optional
  if (arguments.length < 2) {
    callback = bytes;
    bytes = 32;
  }
  if (typeof callback !== 'function') {
    throw("Callback required");
  }
  crypto.randomBytes(bytes, function(err, buf) {
    if (err) return callback (err);
    return callback(null, bignum.fromBuffer(buf));
  });
};

/*
 * The server key exchange message also contains the server's public
 * value (B).  The server calculates this value as B = k*v + g^b % N,
 * where b is a random number that SHOULD be at least 256 bits in length
 * and k = H(N | PAD(g)).
 *
 * Note: as the tests imply, the entire expression is mod N.
 *
 * params:
 *         v (bignum)       verifier
 *         g (bignum)       generator
 */
var getB = exports.getB = function getB(v, g, b, N, alg) {
  alg = alg || ALG;
  var k = getk(N, g, alg);
  var r = k.mul(v).add(g.powm(b, N)).mod(N);
  return r;
};

/*
 * The client key exchange message carries the client's public value
 * (A).  The client calculates this value as A = g^a % N, where a is a
 * random number that SHOULD be at least 256 bits in length.
 *
 * Note: for this implementation, we take that to mean 256/8 bytes.
 */
var getA = exports.getA = function getA(g, a, N) {
  if (Math.ceil(a.bitLength() / 8) < 256/8) {
    console.warn("getA: client key length", a.bitLength(), "is less than the recommended 256");
  }
  return g.powm(a, N);
};

/*
 * Random scrambling parameter u
 *
 * params:
 *         A (bignum)       client ephemeral public key
 *         B (bignum)       server ephemeral public key
 *         N (bignum)       group parameter N
 */
var getu = exports.getu = function getu(A, B, N, alg) {
  alg = alg || ALG;
  return bignum(
      crypto
          .createHash(alg)
          .update(pad(A, N))
          .update(pad(B, N))
          .digest('hex'), 16);
};

/*
 * The TLS premaster secret as calculated by the client
 *
 * params:
 *         s (buffer)       salt (read from server)
 *         I (buffer)       user identity (read from user)
 *         P (buffer)       user password (read from user)
 *         N (bignum)       group parameter N (known in advance)
 *         g (bignum)       generator for N (known in advance)
 *         a (bignum)       ephemeral private key (generated for session)
 *         B (bignum)       server ephemeral public key (read from server)
 *
 * returns: bignum
 */
var client_getS = exports.client_getS = function client_getS(s, I, P, N, g, a, B, alg) {
  var A = getA(g, a, N);
  var u = getu(A, B, N, alg);
  var k = getk(N, g, alg);
  var x = getx(s, I, P, alg);
  return B.sub(k.mul(g.powm(x, N))).powm(a.add(u.mul(x)), N).mod(N);
};

/*
 * The TLS premastersecret as calculated by the server
 *
 * params:
 *         s (bignum)       salt (stored on server)
 *         v (bignum)       verifier (stored on server)
 *         N (bignum)       group parameter N (known in advance)
 *         g (bignum)       generator for N (known in advance)
 *         A (bignum)       ephemeral client public key (read from client)
 *         b (bignum)       server ephemeral private key (generated for session)
 *
 * returns: bignum
 */
var server_getS = exports.server_getS = function server_getS(s, v, N, g, A, b, alg) {
  var k = getk(N, g, alg);
  var B = getB(v, g, b, N, alg);
  var u = getu(A, B, N, alg);
  return A.mul(v.powm(u, N)).powm(b, N).mod(N);
};

/*
 * Compute the shared session key K from S
 *
 * params:
 *         S (bignum)       Session key
 *
 * returns: bignum
 */
var getK = exports.getK = function getK(S, N, alg) {
  alg = alg || ALG;
  var S_pad = new Buffer(pad(S, N));
  return bignum(
    crypto
      .createHash(alg)
      .update(S_pad)
      .digest('hex'), 16);
};

