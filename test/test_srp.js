const vows = require('vows'),
      assert = require('assert'),
      bignum = require('bignum'),
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
        },

        "server rejects bad A": function() {
          // client's "A" must be 1..N-1 . Reject 0 and N and 2*N.
          var Azero = new Buffer(N.length);
          Azero.fill(0, 0, N.length);
          var AN = N;
          var A2N = bignum.fromBuffer(N).mul(2).toBuffer();
          assert.throws(function() {
            srp.server_getS(s, v, N, g, Azero, b, ALG_NAME);
          }, Error);
          assert.throws(function() {
            srp.server_getS(s, v, N, g, AN, b, ALG_NAME);
          }, Error);
          assert.throws(function() {
            srp.server_getS(s, v, N, g, A2N, b, ALG_NAME);
          }, Error);
        },

        "client rejects bad B": function() {
          // server's "B" must be 1..N-1 . Reject 0 and N and 2*N.
          var Bzero = new Buffer(N.length);
          Bzero.fill(0, 0, N.length);
          var BN = N;
          var B2N = bignum.fromBuffer(N).mul(2).toBuffer();
          assert.throws(function() {
            srp.client_getS(s, I, P, N, g, a, Bzero, ALG_NAME);
          }, Error);
          assert.throws(function() {
            srp.client_getS(s, I, P, N, g, a, BN, ALG_NAME);
          }, Error);
          assert.throws(function() {
            srp.client_getS(s, I, P, N, g, a, B2N, ALG_NAME);
          }, Error);
        }

      }
    }
  }
})

.export(module);
