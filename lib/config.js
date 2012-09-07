const convict = require('convict');

var conf = module.exports = convict({
  alg: {
    doc: "Name of secure hash algorithm to use",
    format: 'string = "sha256"',
    env: 'HASH_ALGORITHM'
  },

  N: {
    doc: "Size of N",
    format: 'integer = 2048',
    env: 'N_BITS'
  }
});
