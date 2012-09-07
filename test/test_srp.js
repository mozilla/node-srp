const vows = require('vows'),
      assert = require('assert'),
      bigint = require('bigint'),
      params = require('../lib/params'),
      ALG = 'sha256',
      srp = require('../lib/srp');

vows.describe("srp.js")

.addBatch({
  "Salt": {
    "can be a string": function() {
      assert(srp.getx("i am a string", "alice", "password123", ALG).bitLength() > 0);
    },

    "can be a buffer": function() {
      assert(srp.getx(new Buffer(bigint("DEADBEEF")), "alice", "password123", ALG).bitLength() > 0);
    }
  }
})

.export(module);