const crypto = require('crypto'),
      bignum = require('bignum'),
      assert = require('assert');

const zero = bignum(0);

function assert_(val, msg) {
  if (!val)
    throw new Error(msg||"assertion");
}

/*
 * If a conversion is explicitly specified with the operator PAD(),
 * the integer will first be implicitly converted, then the resultant
 * byte-string will be left-padded with zeros (if necessary) until its
 * length equals the implicitly-converted length of N.
 *
 * params:
 *         n (buffer)       Number to pad
 *         len (int)        length of the resulting Buffer
 *
 * returns: buffer
 */
function padTo(n, len) {
  assertIsBuffer(n, "n");
  var padding = len - n.length;
  assert_(padding > -1, "Negative padding.  Very uncomfortable.");
  var result = new Buffer(len);
  result.fill(0, 0, padding);
  n.copy(result, padding);
  assert.equal(result.length, len);
  return result;
};

function padToN(number, params) {
  assertIsBignum(number);
  return padTo(number.toBuffer(), params.N_length_bits/8);
}

function assertIsBuffer(arg, argname) {
  argname = argname || "arg";
  assert_(Buffer.isBuffer(arg), "Type error: "+argname+" must be a buffer");
}

function assertIsNBuffer(arg, params, argname) {
  argname = argname || "arg";
  assert_(Buffer.isBuffer(arg), "Type error: "+argname+" must be a buffer");
  assert.equal(arg.length, params.N_length_bits/8);
}

function assertIsBignum(arg) {
  assert.equal(arg.constructor.name, "BigNum");
}

/*
 * compute the intermediate value x as a hash of three buffers:
 * salt, identity, and password.  And a colon.  FOUR buffers.
 *
 *      x = H(s | H(I | ":" | P))
 *
 * params:
 *         salt (buffer)    salt
 *         I (buffer)       user identity
 *         P (buffer)       user password
 *
 * returns: x (bignum)      user secret
 */
function getx(params, salt, I, P) {
  assertIsBuffer(salt, "salt (salt)");
  assertIsBuffer(I, "identity (I)");
  assertIsBuffer(P, "password (P)");
  var hashIP = crypto.createHash(params.hash)
    .update(Buffer.concat([I, new Buffer(':'), P]))
    .digest();
  var hashX = crypto.createHash(params.hash)
    .update(salt)
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
 *         params (obj)     group parameters, with .N, .g, .hash
 *         salt (buffer)    salt
 *         I (buffer)       user identity
 *         P (buffer)       user password
 *
 * returns: bignum
 */
function getv(params, salt, I, P) {
  assertIsBuffer(salt, "salt (salt)");
  assertIsBuffer(I, "identity (I)");
  assertIsBuffer(P, "password (P)");
  return params.g.powm(getx(params, salt, I, P), params.N);
};

function getkBuffer(params) {
  return crypto
    .createHash(params.hash)
    .update(padToN(params.N, params))
    .update(padToN(params.g, params))
    .digest();
}

/*
 * calculate the SRP-6 multiplier
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *
 * returns: bignum
 */
function getk(params) {
  return bignum.fromBuffer(getkBuffer(params));
};

/*
 * Generate a random key
 *
 * params:
 *         bytes (int)      length of key (default=32)
 *         callback (func)  function to call with err,key
 *
 * returns: nothing, but runs callback with a Buffer
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
 *         params (obj)     group parameters, with .N, .g, .hash
 *         v (bignum)       verifier (stored)
 *         b (bignum)       server secret exponent
 *
 * returns: B (bignum)      the server public message
 */
function getB(params, v, b) {
  assertIsBignum(v);
  assertIsBignum(b);
  var k = getk(params);
  var N = params.N;
  var r = k.mul(v).add(params.g.powm(b, N)).mod(N);
  return r;
};

/*
 * The client key exchange message carries the client's public value
 * (A).  The client calculates this value as A = g^a % N, where a is a
 * random number that SHOULD be at least 256 bits in length.
 *
 * Note: for this implementation, we take that to mean 256/8 bytes.
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         a (bignum)       client secret exponent
 *
 * returns A (bignum)       the client public message
 */
function getA(params, a) {
  assertIsBignum(a);
  if (Math.ceil(a.bitLength() / 8) < 256/8) {
    console.warn("getA: client key length", a.bitLength(), "is less than the recommended 256");
  }
  return params.g.powm(a, params.N);
};

/*
 * getuBuffer() hashes the two public messages together, to obtain a
 * scrambling parameter "u" which cannot be predicted by either party ahead
 * of time. This makes it safe to use the message ordering defined in the
 * SRP-6a paper, in which the server reveals their "B" value before the
 * client commits to their "A" value.
 *
 * params:
 *        params (obj)    group parameters, with .N, .g, .hash
 *        A (buffer)      client public message
 *        B (buffer)      server public message
 *
 * returns u (Buffer)     shared scrambling parameter
 */
function getuBuffer(params, A, B) {
  assertIsBuffer(A);
  assertIsBuffer(B);
  return crypto
    .createHash(params.hash)
    .update(padTo(A, params.N_length_bits/8))
    .update(padTo(B, params.N_length_bits/8))
    .digest();
}

/*
 * Random scrambling parameter u
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         A (bignum)       client ephemeral public key
 *         B (bignum)       server ephemeral public key
 *
 * returns: u (bignum)      shared scrambling parameter
 */
function getu(params, A, B) {
  assertIsBignum(A);
  assertIsBignum(B);
  return bignum.fromBuffer(getuBuffer(params, A.toBuffer(), B.toBuffer()));
};

/*
 * The TLS premaster secret as calculated by the client
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         salt (buffer)    salt (read from server)
 *         I (buffer)       user identity (read from user)
 *         P (buffer)       user password (read from user)
 *         a (bignum)       ephemeral private key (generated for session)
 *         B (bignum)       server ephemeral public key (read from server)
 *
 * returns: bignum
 */
function client_getS(params, salt, I, P, a, B) {
  assertIsBuffer(salt);
  assertIsBuffer(I);
  assertIsBuffer(P);
  assertIsBignum(a);
  assertIsBignum(B);
  var g = params.g;
  var N = params.N;
  if (zero.ge(B) || N.le(B))
    throw new Error("invalid server-supplied 'B', must be 1..N-1");
  var A = getA(params, a);
  var u = getu(params, A, B);
  var k = getk(params);
  var x = getx(params, salt, I, P);
  return B.sub(k.mul(g.powm(x, N))).powm(a.add(u.mul(x)), N).mod(N);
};

/*
 * The TLS premastersecret as calculated by the server
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         v (bignum)       verifier (stored on server)
 *         A (bignum)       ephemeral client public key (read from client)
 *         b (bignum)       server ephemeral private key (generated for session)
 *
 * returns: bignum
 */
function server_getS(params, v, A, b) {
  assertIsBignum(v);
  assertIsBignum(A);
  assertIsBignum(b);
  var N = params.N;
  if (zero.ge(A) || N.le(A))
    throw new Error("invalid client-supplied 'A', must be 1..N-1");
  var k = getk(params);
  var B = getB(params, v, b);
  var u = getu(params, A, B);
  return A.mul(v.powm(u, N)).powm(b, N).mod(N);
};

/*
 * Compute the shared session key K from S
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         S (buffer)       Session key
 *
 * returns: buffer
 */
function getK(params, S) {
  assertIsBuffer(S);
  var S_pad = padTo(S, params.N_length_bits/8);
  return crypto
      .createHash(params.hash)
      .update(S_pad)
      .digest();
};

function getM(params, A, B, S) {
  assertIsBuffer(A);
  assertIsBuffer(B);
  assertIsBuffer(S);
  return crypto
    .createHash(params.hash)
    .update(padTo(A, params.N_length_bits/8))
    .update(padTo(B, params.N_length_bits/8))
    .update(padTo(S, params.N_length_bits/8))
    .digest();
}

module.exports = {
  getx: function (params, salt, I, P) {
    return getx(params, salt, I, P).toBuffer();
  },
  getv: function (params, salt, I, P) {
    return getv(params, salt, I, P).toBuffer();
  },
  genKey: genKey,
  getB: function (params, v, b) {
    return getB(params, bignum.fromBuffer(v), bignum.fromBuffer(b)).toBuffer();
  },
  getA: function (params, a) {
    return getA(params, bignum.fromBuffer(a)).toBuffer();
  },
  client_getS: function (params, salt, I, P, a, B) {
    return client_getS(params, salt, I, P,
                       bignum.fromBuffer(a), bignum.fromBuffer(B)).toBuffer();
  },
  server_getS: function (params, v, A, b) {
    return server_getS(params, bignum.fromBuffer(v),
                       bignum.fromBuffer(A), bignum.fromBuffer(b)).toBuffer();
  },
  getu: getuBuffer,
  getk: getkBuffer,
  getK: getK,
  getM: getM
}
