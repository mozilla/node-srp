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
  P: h('5b597db7 13ef1c05 67f8d053 e9dde294 f917a0a8 38ddb661 a98a67a1 88bdf491'),
  salt: h('00f100000000000000000000000000000000000000000000000000000000009b'),
  // a and b are usually random. For testing, we force them to specific values.
  a: h(' 00f20000 00000000 00000000 00000000 00000000 00000000 00000000 00000000'
       +'00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000'
       +'00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000'
       +'00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000'
       +'00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000'
       +'00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000'
       +'00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000'
       +'00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000115c'
      ),
  b: h(' 00f30000 00000000 00000000 00000000 00000000 00000000 00000000 00000000'
       +'00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000'
       +'00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000'
       +'00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000'
       +'00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000'
       +'00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000'
       +'00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000'
       +'00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000020'
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
  x: h('ffd36e11 f577d312 89233481 0d55089c b96c3944 3c255a9d 85874bb6 df69a537'),
  v: h(' 00901a4e 05a7986c fafe2c80 993f6e21 847d38b8 b9168065 14948072 2d008c9a'
       +'c5fe418d 799d03c2 b1c26db2 afcd4513 0a0601d3 10faa060 cc728888 aba130a1'
       +'7d855773 107ecc92 f31ea3a3 838bc727 77fc2642 0ed59918 298583d1 5640b965'
       +'939dd696 7e943bd6 ed846dbb b18885c7 4f6e9370 e4eeecc4 c8e2a648 850cf2ba'
       +'5baab188 88b433c4 b0bd8891 eeffe16c c022a098 284696bc 3a81e735 a1a2a371'
       +'62f62b98 0879bbd4 03ae5554 8b9feeec b18bf074 0f0d078a 435fedb5 324d630e'
       +'8a14fed4 35fbb5ea 4b6e94b8 b129799d 2a099167 1a67be34 149dc5e9 4a4a3d05'
       +'749fc3b9 e1a53282 96b20a15 348420be d2f28d25 58cb4099 f30be8a7 240c9252'
      ),
  // 'B' is the server's public message
  B: h(' 00857f70 b197a6f3 f79c4270 a41c581d 62c7ec7f c554c797 481d4b40 75b06be3'
       +'df7f4f18 9e71fbec 08d1bcff 8c5e4f74 65256cba 8a78b725 daa0b9bd dcbbea43'
       +'d916067b 12c59aaf 4a9cdad5 3e08e4a5 770ea722 87987302 2c5f5f60 8eb94795'
       +'710a907e 1b425080 688d9e77 90ce0781 6e6b2cdb 9ad2c18f 60a2a5fe b91b6da3'
       +'92579c5e b1e36f42 5b85c340 85b216b9 7c4a3f7f feb887c8 78ce0152 d8be66eb'
       +'9c7a51ab bae3b3f6 56c6e56d 95d3e148 a23af3e9 aaa54c72 cde19b58 bdcbfb34'
       +'b9eb7f6d cbcd86e2 7e6221f6 d3da2517 255088f5 e7c408b3 7d676512 0134b719'
       +'86287225 d781c49a e5436b89 525e17eb dcb8f3b7 eb43163a cfb31c45 a51a5267'
      ),
  // 'A' is the client's public message
  A: h(' 00f2a357 d7da7132 1be6c070 fb3a5928 8cec951c b13e7645 1f8c466a b373626a'
       +'7272dc14 84c79ea3 cd1ea32e 57fa4665 2e6450aa 61ac5ee7 eac7a8c0 6c28ab19'
       +'5ccbe575 00062c50 1a15fbb2 3a7f71b2 35448326 af5e51c0 63f16737 8c782137'
       +'93dbc54e fb32f204 de753d7a 6b3d826d aaefc007 d17862af 9b6a14e3 5f17f1eb'
       +'8b13c7b8 ffa1f6f4 7b70d62b d0c351b4 7596b0b0 abcba95c 2d731869 ed6e4ec2'
       +'4ab90da8 cb22e65d 256315ee 84d8079b 4086d90c 4e827b51 bb4e4d2d 7b387da0'
       +'2e6b4890 4a3ba6d7 648a9bcd f3e9fc60 7cfba92f 8eacae12 3ac45a79 307cf3dd'
       +'281ed75a 96c7de8f cd823f14 8dcc0634 9795f825 fb029859 b963ab88 320133de'
      ),
  // 'u' combines the two public messages
  u: h('610c6df1 f495e429 8a2a59a0 f5b00d47 ea2ed6ce 2ccec8f7 ade15831 4a7bd794'),
  // 'S' is the shared secret
  S: h(' 009cc8da 2f7a9501 5bc0091f aa36d6ef ff52c33b 924353e1 1de1d8e7 38654d6f'
       +'6a481003 acb17cae 2ba2d4ae 3fea8431 4c940397 640fce92 d9153dff b7f3bd29'
       +'cbdb49e4 ff0d26c4 67061337 fd370851 4e3039d2 4cb54dc4 6420426b 0daf7724'
       +'63fe06eb 1521c7b0 96c4eeb6 e5f9f739 49dcc74b c91baab8 398aff6d f6735da2'
       +'c9486a64 5a20f2d7 d8f455a2 bd226f21 e127f23e 202b21fd d4ef64dc 1a6740b6'
       +'fcd2a6b0 32fcb393 a2b9d975 06b6fb89 5585d291 73cc0e89 c3b3077f fa31215d'
       +'b602b283 64f81012 46ee9e8c 47b63881 f3f867e6 7971825d f6a881d1 142989ab'
       +'cd4abba9 c27ae529 c31be53f 69966ccb 81f7660f 95d5f8fc 45d052df 3bcbb761'
      ),
  // 'K' is the shared derived key
  K: h('78a36d3e 0df089e7 29a98dee 3290fc49 64cd6ec9 6b771d6a bb6efe91 81be868b'),
  // 'M1' is the client's proof that it knows the shared key
  M1: h('182ff265 23922c52 559cab3c dfc89a74 c986b1d7 504ea53d 11d9a204 fc54449d')
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
