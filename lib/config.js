const convict = require('convict');

var conf = module.exports = convict({
  alg_name: {
    doc: "Name of secure hash algorithm to use",
    format: 'string = "sha256"',
    env: 'HASH_ALGORITHM'
  },

  N_bits: {
    doc: "Size of N",
    format: 'integer = 2048',
    env: 'N_BITS'
  },

  s_bytes: {
    doc: "Bytes in salt",
    format: 'integer = 32',
    env: 'S_BYTES'
  },

  server: {
    port: {
      doc: "Port to run SRP server on",
      format: 'integer = 3000',
      env: 'PORT'
    }
  }

});
