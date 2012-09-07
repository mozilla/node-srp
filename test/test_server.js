const vows = require('vows'),
      assert = require('assert'),
      srp = require('../lib/srp'),
      http = require('http'),
      app = require('../app');

var port = 0;

vows.describe('server')

.addBatch({
  "The server": {
    topic: function() {
      var cb = this.callback;
      app.listen(port, function(err) {
        port = app.get('port');
        return cb(err, port);
      });
    },

    "is running": function(port) {
      assert(port !== 0);
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