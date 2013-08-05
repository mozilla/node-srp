const crypto = require('crypto'),
      bignum = require('bignum'),
      assert = require('assert'),
      ALG = 'sha256';

const zero = bignum(0);

/*
 * If a conversion is explicitly specified with the operator PAD(),
 * the integer will first be implicitly converted, then the resultant
 * byte-string will be left-padded with zeros (if necessary) until its
 * length equals the implicitly-converted length of N.
 *
 * params:
 *         n (buffer)       Number to pad
 *         N (buffer)       N
 *
 * returns: buffer
 */
function pad(n, N) {
  var padding = N.length - n.length;
  assert(padding > -1, "Negative padding.  Very uncomfortable.");
  var result = new Buffer(N.length);
  result.fill(0, 0, padding);
  n.copy(result, padding);
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
function getx(s, I, P, alg) {
  assert(Buffer.isBuffer(s), "Type error: salt (s) must be a buffer");
  assert(Buffer.isBuffer(I), "Type error: identity (I) must be a buffer");
  assert(Buffer.isBuffer(P), "Type error: password (P) must be a buffer");
  alg = alg || ALG;
  var hashIP = crypto.createHash(alg)
    .update(Buffer.concat([I, new Buffer(':'), P]))
    .digest();
  var hashX = crypto.createHash(alg)
    .update(s)
    .update(hashIP)
    .digest();
  return bignum.fromBuffer(hashX);
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
function getv(s, I, P, N, g, alg) {
  alg = alg || ALG;
  return g.powm(getx(s, I, P, alg), N);
};

function getkBuffer(N, g, alg) {
  alg = alg || ALG;
  return crypto
    .createHash(alg)
    .update(N)
    .update(pad(g, N))
    .digest();
}

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
function getk(N, g, alg) {
  return bignum.fromBuffer(getkBuffer(N.toBuffer(), g.toBuffer(), alg));
};

/*
 * Generate a random key
 *
 * params:
 *         bytes (int)      length of key (default=32)
 *         callback (func)  function to call with err,key
 *
 * returns: buffer
 */
function genKey(bytes, callback) {
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
    return callback(null, buf);
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
function getB(v, g, b, N, alg) {
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
function getA(g, a, N) {
  if (Math.ceil(a.bitLength() / 8) < 256/8) {
    console.warn("getA: client key length", a.bitLength(), "is less than the recommended 256");
  }
  return g.powm(a, N);
};

function getuBuffer(A, B, N, alg) {
  alg = alg || ALG;
  return crypto
    .createHash(alg)
    .update(pad(A, N))
    .update(pad(B, N))
    .digest()
}

/*
 * Random scrambling parameter u
 *
 * params:
 *         A (bignum)       client ephemeral public key
 *         B (bignum)       server ephemeral public key
 *         N (bignum)       group parameter N
 */
function getu(A, B, N, alg) {
  return bignum.fromBuffer(getuBuffer(A.toBuffer(), B.toBuffer(), N.toBuffer(), alg));
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
function client_getS(s, I, P, N, g, a, B, alg) {
  if (zero.ge(B) || N.le(B))
    throw new Error("invalid server-supplied 'B', must 1..N-1");
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
function server_getS(s, v, N, g, A, b, alg) {
  if (zero.ge(A) || N.le(A))
    throw new Error("invalid client-supplied 'A', must 1..N-1");
  var k = getk(N, g, alg);
  var B = getB(v, g, b, N, alg);
  var u = getu(A, B, N, alg);
  return A.mul(v.powm(u, N)).powm(b, N).mod(N);
};

/*
 * Compute the shared session key K from S
 *
 * params:
 *         S (buffer)       Session key
 *         N (buffer)       group parameter N
 *
 * returns: buffer
 */
function getK(S, N, alg) {
  alg = alg || ALG;
  var S_pad = pad(S, N);
  return crypto
      .createHash(alg)
      .update(S_pad)
      .digest();
};

function getM(A, B, S, N, alg) {
  alg = alg || ALG;
  return crypto
    .createHash(alg)
    .update(pad(A, N))
    .update(pad(B, N))
    .update(pad(S, N))
    .digest()
}

module.exports = {
  getx: function (s, I, P, alg) {
    return getx(s, I, P, alg).toBuffer()
  },
  getv: function (s, I, P, N, g, alg) {
    return getv(
      s,
      I,
      P,
      bignum.fromBuffer(N),
      bignum.fromBuffer(g),
      alg
    ).toBuffer()
  },
  genKey: genKey,
  getB: function (v, g, b, N, alg) {
    return getB(
      bignum.fromBuffer(v),
      bignum.fromBuffer(g),
      bignum.fromBuffer(b),
      bignum.fromBuffer(N),
      alg
    ).toBuffer()
  },
  getA: function (g, a, N) {
    return getA(
      bignum.fromBuffer(g),
      bignum.fromBuffer(a),
      bignum.fromBuffer(N)
    ).toBuffer()
  },
  client_getS: function (s, I, P, N, g, a, B, alg) {
    return client_getS(
      s,
      I,
      P,
      bignum.fromBuffer(N),
      bignum.fromBuffer(g),
      bignum.fromBuffer(a),
      bignum.fromBuffer(B),
      alg
    ).toBuffer()
  },
  server_getS: function (s, v, N, g, A, b, alg) {
    return server_getS(
      bignum.fromBuffer(s),
      bignum.fromBuffer(v),
      bignum.fromBuffer(N),
      bignum.fromBuffer(g),
      bignum.fromBuffer(A),
      bignum.fromBuffer(b),
      alg
    ).toBuffer()
  },
  getu: getuBuffer,
  getk: getkBuffer,
  getK: getK,
  getM: getM
}
