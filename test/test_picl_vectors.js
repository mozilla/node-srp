const vows = require('vows'),
      assert = require('assert'),
      bignum = require('bignum'),
      srp = require('../lib/srp');

/*
 * Vectors from https://wiki.mozilla.org/Identity/AttachedServices/KeyServerProtocol
 *
 * Verify that we are inter-compatible with the SRP implementation used by
 * Mozilla's Identity-Attached Services, aka PiCl (Profile in the Cloud).
 *
 * Note that P is the HKDF-stretched key, computed elsewhere.
 */

function padbuf(b, LEN) {
  assert(b.length <= LEN);
  if (b.length != LEN) {
    var newb = Buffer(LEN);
    newb.fill(0);
    b.copy(newb, LEN-b.length);
    assert(newb.length == LEN);
    b = newb;
  }
  return b;
}
function buf2048(b) {
  return padbuf(b, 2048/8);
}

function join(s) {
  return s.split(/\s/).join('');
}
function decimal(s) {
  return bignum(join(s), 10).toBuffer();
}
function h(s) {
  return new Buffer(join(s), 'hex');
}

const params = require('../lib/params')['2048'];
const ALG = 'sha256';
const inputs = {
  I: new Buffer('andré@example.org', 'utf8'),
  P: h('00f9b71800ab5337 d51177d8fbc682a3 653fa6dae5b87628 eeec43a18af59a9d'),
  salt: h('00f1000000000000000000000000000000000000000000000000000000000179'),
  // a and b are usually random. For testing, we force them to specific values.
  a: h(' 00f2000000000000 0000000000000000 0000000000000000 0000000000000000'
       +'0000000000000000 0000000000000000 0000000000000000 0000000000000000'
       +'0000000000000000 0000000000000000 0000000000000000 0000000000000000'
       +'0000000000000000 0000000000000000 0000000000000000 0000000000000000'
       +'0000000000000000 0000000000000000 0000000000000000 0000000000000000'
       +'0000000000000000 0000000000000000 0000000000000000 0000000000000000'
       +'0000000000000000 0000000000000000 0000000000000000 0000000000000000'
       +'0000000000000000 0000000000000000 0000000000000000 000000000000d3d7'
      ),
  b: h(' 00f3000000000000 0000000000000000 0000000000000000 0000000000000000'
       +'0000000000000000 0000000000000000 0000000000000000 0000000000000000'
       +'0000000000000000 0000000000000000 0000000000000000 0000000000000000'
       +'0000000000000000 0000000000000000 0000000000000000 0000000000000000'
       +'0000000000000000 0000000000000000 0000000000000000 0000000000000000'
       +'0000000000000000 0000000000000000 0000000000000000 0000000000000000'
       +'0000000000000000 0000000000000000 0000000000000000 0000000000000000'
       +'0000000000000000 0000000000000000 0000000000000000 000000000000000f'
      )
};

/* The constants below are the expected computed SRP values given the
 * parameters specified above for N/g, I, P, a, and b.
 */

const expected = {
  // 'k' encodes the group (N and g), used in SRP-6a
  k: decimal('2590038599070950300691544216303772122846747035652616593381637186118123578112'),
  // 'x' is derived from the salt and password
  // 'v' is the SRP verifier
  x: h('b5200337cc3f3f92 6cdddae0b2d31029 c069936a844aff58 779a545be89d0abe'),
  v: h(' 00173ffa0263e63c cfd6791b8ee2a40f 048ec94cd95aa8a3 125726f9805e0c82'
       +'83c658dc0b607fbb 25db68e68e93f265 8483049c68af7e82 14c49fde2712a775'
       +'b63e545160d64b00 189a86708c69657d a7a1678eda0cd79f 86b8560ebdb1ffc2'
       +'21db360eab901d64 3a75bf1205070a57 91230ae56466b8c3 c1eb656e19b794f1'
       +'ea0d2a077b3a7553 50208ea0118fec8c 4b2ec344a05c66ae 1449b32609ca7189'
       +'451c259d65bd15b3 4d8729afdb5faff8 af1f3437bbdc0c3d 0b069a8ab2a959c9'
       +'0c5a43d42082c774 90f3afcc10ef5648 625c0605cdaace6c 6fdc9e9a7e6635d6'
       +'19f50af773452247 0502cab26a52a198 f5b00a2798589165 07b0b4e9ef9524d6'),
  // 'B' is the server's public message
  B: h(' 0022ce5a7b9d8127 7172caa20b0f1efb 4643b3becc535664 73959b07b790d3c3'
       +'f08650d5531c19ad 30ebb67bdb481d1d 9cf61bf272f84398 48fdda58a4e6abc5'
       +'abb2ac496da5098d 5cbf90e29b4b110e 4e2c033c70af7392 5fa37457ee13ea3e'
       +'8fde4ab516dff1c2 ae8e57a6b264fb9d b637eeeae9b5e43d faba9b329d3b8770'
       +'ce89888709e02627 0e474eef822436e6 397562f284778673 a1a7bc12b6883d1c'
       +'21fbc27ffb3dbeb8 5efda279a69a1941 4969113f10451603 065f0a0126666456'
       +'51dde44a52f4d8de 113e2131321df1bf 4369d2585364f9e5 36c39a4dce33221b'
       +'e57d50ddccb4384e 3612bbfd03a268a3 6e4f7e01de651401 e108cc247db50392'),
  // 'A' is the client's public message
  A: h(' 007da76cb7e77af5 ab61f334dbd5a958 513afcdf0f47ab99 271fc5f7860fe213'
       +'2e5802ca79d2e5c0 64bb80a38ee08771 c98a937696698d87 8d78571568c98a1c'
       +'40cc6e7cb101988a 2f9ba3d65679027d 4d9068cb8aad6ebf f0101bab6d52b5fd'
       +'fa81d2ed48bba119 d4ecdb7f3f478bd2 36d5749f2275e948 4f2d0a9259d05e49'
       +'d78a23dd26c60bfb a04fd346e5146469 a8c3f010a627be81 c58ded1caaef2363'
       +'635a45f97ca0d895 cc92ace1d09a99d6 beb6b0dc0829535c 857a419e834db128'
       +'64cd6ee8a843563b 0240520ff0195735 cd9d316842d5d3f8 ef7209a0bb4b54ad'
       +'7374d73e79be2c39 75632de562c59647 0bb27bad79c3e2fc ddf194e1666cb9fc'),
  // 'u' combines the two public messages
  u: h('b284aa1064e87751 50da6b5e2147b47c a7df505bed94a6f4 bb2ad873332ad732'),
  // 'S' is the shared secret
  S: h(' 0092aaf0f527906a a5e8601f5d707907 a03137e1b601e04b 5a1deb02a981f4be'
       +'037b39829a27dba5 0f1b27545ff2e287 29c2b79dcbdd32c9 d6b20d340affab91'
       +'a626a8075806c26f e39df91d0ad979f9 b2ee8aad1bc783e7 097407b63bfe58d9'
       +'118b9b0b2a7c5c4c debaf8e9a460f4bf 6247b0da34b760a5 9fac891757ddedca'
       +'f08eed823b090586 c63009b2d740cc9f 5397be89a2c32cdc fe6d6251ce11e44e'
       +'6ecbdd9b6d93f30e 90896d2527564c7e b9ff70aa91acc0ba c1740a11cd184ffb'
       +'989554ab58117c21 96b353d70c356160 100ef5f4c28d19f6 e59ea2508e8e8aac'
       +'6001497c27f362ed bafb25e0f045bfdf 9fb02db9c908f103 40a639fe84c31b27'),
  // 'K' is the shared derived key
  K: h('e68fd0112bfa31dc ffc8e9c96a1cbadb 4c3145978ff35c73 e5bf8d30bbc7499a'),
  // 'M1' is the client's proof that it knows the shared key
  M1: h('27949ec1e0f16256 33436865edb037e2 3eb6bf5cb91873f2 a2729373c2039008')
};


function hexequal(a, b) {
  assert.equal(a.length, b.length);
  assert.equal(a.toString('hex'), b.toString('hex'));
}

vows.describe('picl vectors')

.addBatch({
  'test vectors': {
    'I encoding': function() {
      hexequal(inputs.I, new Buffer('616e6472c3a9406578616d706c652e6f7267', "hex"));
    },

    'getk': function() {
      hexequal(srp.getk(params.N, params.g, ALG), expected.k);
    },

    'getx': function() {
      hexequal(srp.getx(inputs.salt, inputs.I, inputs.P, ALG), expected.x);
    },

    'getv': function() {
      hexequal(buf2048(srp.getv(inputs.salt, inputs.I, inputs.P, params.N, params.g, ALG)), expected.v);
    },

    'getB (on server)': function() {
      var B = srp.getB(expected.v, params.g, inputs.b, params.N, ALG);
      hexequal(buf2048(B), expected.B);
    },

    'getA (on client)': function() {
      var A = srp.getA(params.g, inputs.a, params.N);
      hexequal(buf2048(A), expected.A);
    },

    'getu': function() {
      var u = srp.getu(expected.A, expected.B, params.N, ALG);
      hexequal(u, expected.u);
    },

    'secrets': {
      'client': {
        topic: function() {
          return srp.client_getS(inputs.salt, inputs.I, inputs.P, params.N, params.g, inputs.a, expected.B, ALG);
        },

        'S': function(S) {
          hexequal(buf2048(S), expected.S);
        },

        'K': function(S) {
          hexequal(srp.getK(S, params.N, ALG), expected.K);
        }

      },

      'server': {
        topic: function() {
          return srp.server_getS(inputs.salt, expected.v, params.N, params.g, expected.A, inputs.b, ALG);
        },

        'S': function(S) {
          hexequal(buf2048(S), expected.S);
        },

        'K': function(S) {
          hexequal(srp.getK(S, params.N, ALG), expected.K);
        }
      }
    }
  }
})

.export(module);
