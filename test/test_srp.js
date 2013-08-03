const vows = require('vows'),
      assert = require('assert'),
      params = require('../lib/params'),
      srp = require('../lib/srp'),
      s = new Buffer("salty"),
      I = new Buffer("alice"),
      P = new Buffer("password123"),
      N = params[4096].N,
      g = params[4096].g,
      ALG_NAME = 'sha256';

var a, A;
var b, B;
var v;
var S_client, S_server;

vows.describe("srp.js")

.addBatch({
  "getv": function() {
    v = srp.getv(s, I, P, N, g, ALG_NAME);
    assert(v.length > 0);
  },

  "getx": function() {
    assert(srp.getx(s, I, P, ALG_NAME).length > 0);
  },

  "with a": {
    topic: function() {
      var cb = this.callback;
      srp.genKey(64, function(err, key) {
        a = key;
        cb(err, a);
      });
    },

    "getA": function(err, a) {
      assert(err === null);

      A = srp.getA(g, a, N);
      assert(A.length > 0);
    },

    "with b": {
      topic: function() {
        var cb = this.callback;
        srp.genKey(32, function(err, key) {
          b = key;
          cb(err, b);
        });
      },

      "getB": function(err, b) {
        assert(err === null);

        B = srp.getB(v, g, b, N, ALG_NAME);
        assert(B.length > 0);
      },

      "getS": {
        "by client": function() {
          S_client = srp.client_getS(s, I, P, N, g, a, B, ALG_NAME);
          assert(S_client.length > 0);
        },

        "by server": function() {
          S_server = srp.server_getS(s, v, N, g, A, b, ALG_NAME);
          assert(S_server.length > 0);
        },

        "by client and server are equal": function() {
          assert.equal(S_server.toString('hex'), S_client.toString('hex'));
        }
      }
    }
  }
})

.export(module);
