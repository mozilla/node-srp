const vows = require('vows'),
      assert = require('assert'),
      bigint = require('bigint'),
      crypto = require('crypto'),
      srp = require('../lib/srp'),
      params = require('../lib/params'),
      http = require('http'),
      request = require('request'),
      app = require('../server/server');

const I = "Kevin Phillips-Bong";
const P = "slightly silly";
const ALG_NAME = 'sha256';
const KEY_SIZE = '4096';

function H (string_or_buf) {
  return crypto.createHash(ALG_NAME).update(string_or_buf).digest('hex');
}

// these variables will be modified by the tests below
var port = 0;
var s = '';
var g = 0;
var N = 0;
var a = 0;
var A = 0;
var B = 0;
var S = 0;

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
      var uri = 'http://localhost:' + port + '/create';
      var params = {form: {identity: I, password: P, alg_name: ALG_NAME, N_bits: KEY_SIZE}};
      request.post(uri, params, this.callback);
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
          var params = {form: {identity: I, ephemeral_pubkey: A.toString(16)}};
          request.post(uri, params, cb);
        });
      },

      "exchange": function(err, res, body) {
        assert(err === null);
        assert(body === '200');

        s = res.headers.salt;
        B = bigint(res.headers.ephemeral_pubkey, 16);
        assert(s);
        assert(B);
      },

      "and session key": {
        topic: function() {
          S = srp.client_getS(s, I, P, N, g, a, B, ALG_NAME);
          var hhk = H(H(S.toBuffer()));
          var uri = 'http://localhost:' + port + '/confirm';
          var params = {form: {identity: I, challenge: hhk}};
          request.post(uri, params, this.callback);
        },

        "is confirmed on the server for the client": function(err, res, body) {
          assert(err === null);
          assert(body === '200');
        },

        "is confirmed on the client from the server": function(err, res, body) {
          assert(err === null);
          assert(body === '200');

          var serverK = res.headers.challenge;
          assert(serverK === H(S.toBuffer()));
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