const vows = require('vows'),
      assert = require('assert'),
      bignum = require('bignum'),
      params = require('../lib/params')[4096],
      srp = require('../lib/srp'),
      s = new Buffer("salty"),
      I = new Buffer("alice"),
      P = new Buffer("password123");

assert(params, "missing parameters");

var a, A;
var b, B;
var v;
var S_client, S_server;

vows.describe("srp.js")

.addBatch({
  "getv": function() {
    v = srp.getv(params, s, I, P);
    assert(v.length > 0);
  },

  "getx": function() {
    assert(srp.getx(params, s, I, P).length > 0);
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

      A = srp.getA(params, a);
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

        B = srp.getB(params, v, b);
        assert(B.length > 0);
      },

      "getS": {
        "by client": function() {
          S_client = srp.client_getS(params, s, I, P, a, B);
          assert(S_client.length > 0);
        },

        "by server": function() {
          S_server = srp.server_getS(params, v, A, b);
          assert(S_server.length > 0);
        },

        "by client and server are equal": function() {
          assert.equal(S_server.toString('hex'), S_client.toString('hex'));
        },

        "and K and M1 can be generated": function() {
          var K = srp.getK(params, S_client);
          var M1 = srp.getM(params, A, B, S_client);
          assert(K.length > 0);
          assert (M1.length > 0);
        },

        "server rejects bad A": function() {
          // client's "A" must be 1..N-1 . Reject 0 and N and 2*N.
          var Azero = new Buffer(params.N_length_bits/8);
          Azero.fill(0, 0, params.N_length_bits/8);
          var AN = params.N.toBuffer();
          var A2N = params.N.mul(2).toBuffer();
          assert.throws(function() {
            srp.server_getS(params, v, Azero, b);
          }, Error);
          assert.throws(function() {
            srp.server_getS(params, v, AN, b);
          }, Error);
          assert.throws(function() {
            srp.server_getS(params, v, A2N, b);
          }, Error);
        },

        "client rejects bad B": function() {
          // server's "B" must be 1..N-1 . Reject 0 and N and 2*N.
          var Bzero = new Buffer(params.N_length_bits/8);
          Bzero.fill(0, 0, params.N_length_bits/8);
          var BN = params.N.toBuffer();
          var B2N = params.N.mul(2).toBuffer();
          assert.throws(function() {
            srp.client_getS(params, s, I, P, a, Bzero);
          }, Error);
          assert.throws(function() {
            srp.client_getS(params, s, I, P, a, BN);
          }, Error);
          assert.throws(function() {
            srp.client_getS(params, s, I, P, a, B2N);
          }, Error);
        }

      }
    }
  }
})

.export(module);
