const vows = require('vows'),
      assert = require('assert'),
      bigint = require('bigint'),
      crypto = require('crypto'),
      srp = require('../lib/srp'),
      params = require('../lib/params'),
      http = require('http'),
      request = require('request'),
      app = require('../server/server');

const I = new Buffer("Kevin Phillips-Bong");
const P = new Buffer("slightly silly");
const ALG_NAME = 'sha256';
const KEY_SIZE = '4096';
const N = params[KEY_SIZE].N;
const g = params[KEY_SIZE].g;
const SALT_BYTES = 32;

function H (string_or_buf) {
  return crypto.createHash(ALG_NAME).update(string_or_buf).digest('hex');
}

// these variables will be modified by the tests below
var port = 0;
var s = '';
var v = 0;
var A = 0;
var B = 0;
var S = 0;
var hhk = '';
var session_id = '';

vows.describe('server')

.addBatch({
  "The server": {
    topic: function() {
      var cb = this.callback;
      app.listen(port, function(err) {
        port = app.address().port;
        return cb(err, port);
      });
    },

    "is running": function(port) {
      assert(port !== 0);
    }
  }
})

.addBatch({
  "Account": {
    topic: function() {
      var cb = this.callback;
      var uri = 'http://localhost:' + port + '/create';
      // generate s and compute v; send to server
      crypto.randomBytes(SALT_BYTES, function(err, salt) {
        s = salt;
        v = srp.getv(s, I, P, N, g, ALG_NAME);
        var data = {form: {
          identity: I.toString('utf-8'),
          verifier: v.toString(16),
          salt: s.toString('utf-8'),
          alg_name: ALG_NAME,
          N_bits: KEY_SIZE}};
        request.post(uri, data, cb);
      });
    },

    "creation": function(err, res, body) {
      assert(body === '200');
      assert(err === null);
    },

    "ephemeral key": {
      topic: function() {
        var cb = this.callback;
        N = params[KEY_SIZE].N;
        g = params[KEY_SIZE].g;

        srp.genKey(32, function(err, key) {
          a = key;
          A = srp.getA(g, a, N);
          var uri = 'http://localhost:' + port + '/hello';
          var data = {form: {
            identity: I.toString('utf-8'),
            ephemeral_pubkey: A.toString(16)}};
          request.post(uri, data, cb);
        });
      },

      "exchange": function(err, res, body) {
        assert(err === null);
        assert(body === '200');

        assert(!!res.headers.session_id);
        session_id = res.headers.session_id;

        assert(res.headers.salt == s.toString('utf-8'));

        B = bigint(res.headers.ephemeral_pubkey, 16);
        assert(B.ne(0));
        assert(B.ne(A));
      },

      "and session key": {
        topic: function() {
          S = srp.client_getS(s, I, P, N, g, a, B, ALG_NAME);
          hhk = H(H(S.toString(16)));
          var uri = 'http://localhost:' + port + '/confirm';
          var data = {form: {
            identity: I.toString('utf-8'), 
            challenge: hhk, 
            session_id: session_id}};
          request.post(uri, data, this.callback);
        },

        "is confirmed on the server for the client": function(err, res, body) {
          assert(err === null);
          assert(body === '200');
        },

        "is confirmed on the client from the server": function(err, res, body) {
          assert(err === null);
          assert(body === '200');

          assert(res.headers.challenge === H(S.toString(16)));
        }
      }

    }
  }
})

.addBatch({
  "The server": {
    topic: function() {
      return app.close();
    },

    "is stopped": function(err, something) {
      assert(err === null);
    }
  }
})

.export(module);
