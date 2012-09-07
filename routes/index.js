const crypto = require('crypto'),
      bigint = require('bigint'),
      config = require('../lib/config'),
      params = require('../lib/params'),
      S_BYTES = config.get('s_bytes'),
      db = require('../lib/db'),
      srp = require('../lib/srp');

var sessions = {};

/*
 * GET home page.
 */

exports.index = function(req, res){
  res.render('index', { title: 'Express' });
};

/*
 * API methods.  All POST.
 */

/*
 * Create a new account on the server, storing identity, salt, and verifier.
 * The password is discarded.
 *
 * TODO provide a secure way to do this from the client
 *
 * returns: 200 OK on success
 */
exports.create = function(req, res) {
  var I = req.body.identity;
  var P = req.body.password;
  var N_bits = req.body.N_bits || config.get('N_bits');
  var N = params[N_bits].N;
  var g = params[N_bits].g;
  var alg = req.body.alg_name || config.get('alg_name');
  if (! (I && P && N && g && alg)) {
    return res.send(400);
  }

  db.fetch(I, function(err, data) {
    // account exists?
    if (data) return res.send(400);

    crypto.randomBytes(config.get('s_bytes'), function(err, buf) {
      if (err) return res.send(500);
      // base 60 alphanumeric string from buffer
      var s = bigint.fromBuffer(buf).toString(60);
      var v = srp.getv(s, I, P, N, g, alg);
      db.store(I, {s: s, v: v, N_bits: N_bits, alg: alg}, function(err) {
        if (err) return res.send(500);
        return res.send(200);
      });
    });
  });
};

/*
 * /hello - initiate a dialogue
 *
 * store parameters locally, and return a session key to the caller.
 *
 * Required params:
 *     identity (string)          the user's identity
 *     ephemeral_pubkey (string)  hex-encoded key (A)
 *
 * Returns:
 *     salt (string)              stored salt for identity
 *     ephemeral_pubkey (string)  hex-encoded key (B)
 */

exports.hello = function(req, res) {
  var I = req.body.identity;
  var A = bigint(req.body.ephemeral_pubkey, 16);

  if (! (I && A)) {
    return res.send(400);
  }

  db.fetch(I, function(err, data) {
    if (err || !data) {
      // 404 leaks info that identity does not have an account
      // error out with 500?  just as leaky?
      return res.send(404);
    }

    var v = data.v;
    var s = data.s;
    var N = params[data.N_bits].N;
    var g = params[data.N_bits].g;
    var alg = data.alg;

    srp.genKey(function(err, b) {
      if (err) return res.send(500);
      var B = srp.getB(v, g, b, N, alg);
      var u = srp.getu(A, B, N, alg);
      var S = srp.server_getS(s, v, N, g, A, b, alg);

      sessions[I] = {
        v: v,
        b: b,
        B: B,
        u: u,
        S: S,
        alg: alg
      };

      return res.json(200, {salt: s, ephemeral_pubkey: B.toString(16)});
    });
  });
};

/*
 * /exchange - exchange keys
 *
 * If client can send H(H(K)), I'm convinced she has the right key.
 *
 * Required params:
 *     identity (string)          the user's identity
 *     challenge (string)         hex-encoded double-hashed key (H(H(K)))
 *
 * Returns:
 *     challenge:                 hex-encoded hashed key (H(K))
 */
exports.exchange = function(req, res) {
  var I = req.body.identity;
  var HHK = req.body.challenge;
  var i = sessions[I];

  if (! (I && HHK && i && i.alg && i.v && i.b && i.B && i.u && i.S)) {
    delete sessions[I];
    return res.send(400);
  }

  // decode the challenge
  HHK = bigint(HHK, 16);

  function H (buf) {
    return crypto.createHash(i.alg).update(buf);
  }
  var hhk = bigint(H(H(i.S.toBuffer())).digest('hex'), 16);
  console.log("aha!", hhk.toString(16));

  console.log("is??", bigint(H(i.S.toBuffer()).digest('hex'), 16).toString(16));
  // send a hash of K back as our challenge, if the client cares
  return res.send(200, bigint(H(i.S.toBuffer()).digest('hex'), 16).toString(16));
};