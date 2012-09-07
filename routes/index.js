const crypto = require('crypto'),
      bigint = require('bigint'),
      config = require('../lib/config'),
      params = require('../lib/params'),
      S_BYTES = config.get('s_bytes'),
      db = require('../lib/db'),
      srp = require('../lib/srp');

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

  crypto.randomBytes(config.get('s_bytes'), function(err, buf) {
    if (err) return res.send(500);
    // base 60 alphanumeric string from buffer
    var s = bigint.fromBuffer(buf).toString(60);
    var v = srp.getv(s, I, P, N, g, alg);
    db.store(I, {s: s, v: v}, function(err) {
      if (err) return res.send(500);
      return res.send(200);
    });
  });
};

exports.hello = function(req, res) {
  // fetch
};