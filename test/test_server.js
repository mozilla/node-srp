const vows = require('vows'),
      assert = require('assert'),
      bigint = require('bigint'),
      srp = require('../lib/srp'),
      params = require('../lib/params'),
      http = require('http'),
      request = require('request'),
      app = require('../app');

const I = "Kevin Phillips-Bong";
const P = "slightly silly";
const KEY_SIZE = '4096';

// these variables will be modified by the tests below
var port = 0;
var s = '';
var g = 0;
var N = 0;
var a = 0;
var A = 0;
var B = 0;

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
      var params = {form: {identity: I, password: P, alg_name: 'sha256', N_bits: KEY_SIZE}};
      request.post(uri, params, this.callback);
    },

    "creation": function(err, res, body) {
      assert(body === 'OK');
      assert(err === null);
    },

    "key": {
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

        s = res.headers.salt;
        B = bigint(res.headers.ephemeral_pubkey, 16);
        assert(s);
        assert(B);
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