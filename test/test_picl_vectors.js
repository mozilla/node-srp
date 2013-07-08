const vows = require('vows'),
      assert = require('assert'),
      bigint = require('bigint'),
      Put = require('put'),
      params = require('../lib/params'),
      srp = require('../lib/srp');

/*
 * Vectors from https://wiki.mozilla.org/Identity/AttachedServices/KeyServerProtocol
 *
 * Verify that we are inter-compatible with the SRP implementation used by
 * Mozilla's Identity-Attached Services, aka PiCl (Profile in the Cloud).
 *
 * Note that P_stretched is the HKDF-stretched key, computed elsewhere.
 */

const I = new Buffer('andré@example.org', 'utf8'),
      P = new Buffer('pässwörd', 'utf8'),
      P_stretch = new Buffer('5b597db713ef1c0567f8d053e9dde294f917a0a838ddb661a98a67a188bdf491', 'hex');
      N = params['2048'].N,
      g = params['2048'].g,
      s = new Buffer('00f100000000000000000000000000000000000000000000000000000000009b', 'hex'),
      b = bigint(' 1198277 66042000 95785634 94115500 91527197 08125226 96054476'
                +'89936430 95227800 29105361 55503035 27745056 25606029 71778328'
                +'00325345 97331398 44872578 33596964 14341721 63891575 82554932'
                +'02841499 37367218 83155342 80693274 23189198 73686357 51420460'
                +'53414928 39548731 87904313 57183095 39706489 29157321 42348352'
                +'72947679 88835942 53343430 84231300 63326063 44714480 99439808'
                +'86106931 64826214 24231409 08830704 76916770 00983929 68117727'
                +'43420990 99723875 98328292 19109897 32876428 83198548 78234173'
                +'12772399 92628295 46938957 84583632 37146486 38545526 79918828' 
                +'02106605 08721582 00403102 62483181 55961400 94933216 29832845'
                +'62611677 70805044 44704039 04739431 33561758 53336713 78812960', 10),
      a = bigint(' 1193346 47663227 29136311 34057412 43413916 43482736 31461660'
                +'12200067 03889414 28162541 13710841 71663800 88052095 43910927'
                +'47649109 98165425 61560345 50331133 01525500 56221240 12256352'
                +'06121987 03057065 66763757 03406470 63422988 04247319 00591569'
                +'75005813 46381864 66966435 73820202 00036915 26156674 01021816'
                +'29849129 76536206 14440782 97876439 31378219 56464627 16314542'
                +'15793734 39868081 67341567 89864323 26806001 40897576 06109012'
                +'50649711 19889621 34960686 05039486 22864591 67629830 47459546'
                +'90086093 75374681 08474188 47198514 54277570 80362211 87408873'
                +'99628800 12800917 05751238 00497654 06348391 06888223 63866455'
                +'31489818 95205023 68799907 19946264 95152039 36244793 15530076', 10);
      ALG = 'sha256';

/* The constants below are the expected computed SRP values given the
 * parameters specified above for I, P, N, g, b, a, and the algorithm.
 */

const I_hex =    '616e6472c3a9406578616d706c652e6f7267',
      P_hex =    '70c3a4737377c3b67264',
      k = bigint('2590038599070950300691544216303772122846747035652616593381637186118123578112', 10),
      x_hex =    'ffd36e11f577d312892334810d55089cb96c39443c255a9d85874bb6df69a537',
      x = bigint('115713340795669212831971819661984296758573939625477265918747447380376082294071', 10),
      v = bigint('  710597 15947322 36316881 86192315 96014948 50266475 38798215'
                +'26306672 64830126 91363325 46839100 25398380 39127254 13731153'
                +'91662629 79482319 25131054 77620430 12038723 83833825 29286340'
                +'32606803 60596134 07896556 96705692 35971894 13091525 11443851'
                +'64054999 20023879 03995243 80121634 02227132 85297349 37174066'
                +'81150322 72229446 78351915 27535251 17877358 24142082 28132003'
                +'20659513 25711784 70786998 71417330 46865019 26505392 61877568'
                +'70781628 00905313 75741674 26864838 84981432 16212979 18109241'
                +'15157063 80745962 22682772 15853248 49766449 08876686 42378825'
                +'42044011 36102193 24427662 56173851 85761349 29894589 97367433'
                +'46225452 67882212 38212661 40913290 18051354 03998520 50747986', 10),
      v_hex =   ('00901a4e 05a7986c fafe2c80 993f6e21 847d38b8 b9168065 14948072'
                +'2d008c9a c5fe418d 799d03c2 b1c26db2 afcd4513 0a0601d3 10faa060'
                +'cc728888 aba130a1 7d855773 107ecc92 f31ea3a3 838bc727 77fc2642'
                +'0ed59918 298583d1 5640b965 939dd696 7e943bd6 ed846dbb b18885c7'
                +'4f6e9370 e4eeecc4 c8e2a648 850cf2ba 5baab188 88b433c4 b0bd8891'
                +'eeffe16c c022a098 284696bc 3a81e735 a1a2a371 62f62b98 0879bbd4'
                +'03ae5554 8b9feeec b18bf074 0f0d078a 435fedb5 324d630e 8a14fed4'
                +'35fbb5ea 4b6e94b8 b129799d 2a099167 1a67be34 149dc5e9 4a4a3d05'
                +'749fc3b9 e1a53282 96b20a15 348420be d2f28d25 58cb4099 f30be8a7'
                +'240c9252').split(/\s/).join(''),
      b_hex =   ('00f30000 00000000 00000000 00000000 00000000 00000000 00000000'
                +'00000000 00000000 00000000 00000000 00000000 00000000 00000000'
                +'00000000 00000000 00000000 00000000 00000000 00000000 00000000'
                +'00000000 00000000 00000000 00000000 00000000 00000000 00000000'
                +'00000000 00000000 00000000 00000000 00000000 00000000 00000000'
                +'00000000 00000000 00000000 00000000 00000000 00000000 00000000'
                +'00000000 00000000 00000000 00000000 00000000 00000000 00000000'
                +'00000000 00000000 00000000 00000000 00000000 00000000 00000000'
                +'00000000 00000000 00000000 00000000 00000000 00000000 00000000'
                +'00000020').split(/\s/).join(''),
      B_hex =   ('00857f70 b197a6f3 f79c4270 a41c581d 62c7ec7f c554c797 481d4b40'
                +'75b06be3 df7f4f18 9e71fbec 08d1bcff 8c5e4f74 65256cba 8a78b725'
                +'daa0b9bd dcbbea43 d916067b 12c59aaf 4a9cdad5 3e08e4a5 770ea722'
                +'87987302 2c5f5f60 8eb94795 710a907e 1b425080 688d9e77 90ce0781'
                +'6e6b2cdb 9ad2c18f 60a2a5fe b91b6da3 92579c5e b1e36f42 5b85c340'
                +'85b216b9 7c4a3f7f feb887c8 78ce0152 d8be66eb 9c7a51ab bae3b3f6'
                +'56c6e56d 95d3e148 a23af3e9 aaa54c72 cde19b58 bdcbfb34 b9eb7f6d'
                +'cbcd86e2 7e6221f6 d3da2517 255088f5 e7c408b3 7d676512 0134b719'
                +'86287225 d781c49a e5436b89 525e17eb dcb8f3b7 eb43163a cfb31c45'
                +'a51a5267').split(/\s/).join(''),
      a_hex =   ('00f20000 00000000 00000000 00000000 00000000 00000000 00000000'
                +'00000000 00000000 00000000 00000000 00000000 00000000 00000000'
                +'00000000 00000000 00000000 00000000 00000000 00000000 00000000'
                +'00000000 00000000 00000000 00000000 00000000 00000000 00000000'
                +'00000000 00000000 00000000 00000000 00000000 00000000 00000000'
                +'00000000 00000000 00000000 00000000 00000000 00000000 00000000'
                +'00000000 00000000 00000000 00000000 00000000 00000000 00000000'
                +'00000000 00000000 00000000 00000000 00000000 00000000 00000000'
                +'00000000 00000000 00000000 00000000 00000000 00000000 00000000'
                +'0000115c').split(/\s/).join(''),
      A_hex =   ('00f2a357 d7da7132 1be6c070 fb3a5928 8cec951c b13e7645 1f8c466a'
                +'b373626a 7272dc14 84c79ea3 cd1ea32e 57fa4665 2e6450aa 61ac5ee7'
                +'eac7a8c0 6c28ab19 5ccbe575 00062c50 1a15fbb2 3a7f71b2 35448326'
                +'af5e51c0 63f16737 8c782137 93dbc54e fb32f204 de753d7a 6b3d826d'
                +'aaefc007 d17862af 9b6a14e3 5f17f1eb 8b13c7b8 ffa1f6f4 7b70d62b'
                +'d0c351b4 7596b0b0 abcba95c 2d731869 ed6e4ec2 4ab90da8 cb22e65d'
                +'256315ee 84d8079b 4086d90c 4e827b51 bb4e4d2d 7b387da0 2e6b4890'
                +'4a3ba6d7 648a9bcd f3e9fc60 7cfba92f 8eacae12 3ac45a79 307cf3dd'
                +'281ed75a 96c7de8f cd823f14 8dcc0634 9795f825 fb029859 b963ab88'
                +'320133de').split(/\s/).join(''),
      u_hex =    '610c6df1f495e4298a2a59a0f5b00d47ea2ed6ce2ccec8f7ade158314a7bd794',
      S_hex =   ('009cc8da 2f7a9501 5bc0091f aa36d6ef ff52c33b 924353e1 1de1d8e7'
                +'38654d6f 6a481003 acb17cae 2ba2d4ae 3fea8431 4c940397 640fce92'
                +'d9153dff b7f3bd29 cbdb49e4 ff0d26c4 67061337 fd370851 4e3039d2'
                +'4cb54dc4 6420426b 0daf7724 63fe06eb 1521c7b0 96c4eeb6 e5f9f739'
                +'49dcc74b c91baab8 398aff6d f6735da2 c9486a64 5a20f2d7 d8f455a2'
                +'bd226f21 e127f23e 202b21fd d4ef64dc 1a6740b6 fcd2a6b0 32fcb393'
                +'a2b9d975 06b6fb89 5585d291 73cc0e89 c3b3077f fa31215d b602b283'
                +'64f81012 46ee9e8c 47b63881 f3f867e6 7971825d f6a881d1 142989ab'
                +'cd4abba9 c27ae529 c31be53f 69966ccb 81f7660f 95d5f8fc 45d052df'
                +'3bcbb761').split(/\s/).join(''),
      M1_hex =   '182ff26523922c52559cab3cdfc89a74c986b1d7504ea53d11d9a204fc54449d',
      K_hex =    '78a36d3e0df089e729a98dee3290fc4964cd6ec96b771d6abb6efe9181be868b';


function pad(s, margin) {
  margin = margin || 256;
  // We consistently zero-pad all string values to 256 bytes (2048 bits)
  
  var padding = margin - (s.length % margin)
  var prefix = '';
  while (padding-- > 0) {
    prefix += '0';
  }
  return prefix + s; 
};

vows.describe('picl vectors')

.addBatch({
  'test vectors': {
    'I encoding': function() {
      assert(I.toString('hex') == I_hex);
    },

    'P encoding': function() {
      assert(P.toString('hex') == P_hex);
    },

    'k': function() {
      assert(k.eq(srp.getk(N, g, ALG)));
    },

    'x': function() {
      assert(x.toString(16) == x_hex);
      assert(srp.getx(s, I, P_stretch, ALG).eq(x));
    },

    'v': function() {
      assert(pad(v.toString(16)) == v_hex);
      assert(srp.getv(s, I, P_stretch, N, g, ALG).eq(v));
    },

    'b': function() {
      assert(pad(b.toString(16)) == b_hex);
    },

    'a': function() {
      assert(pad(a.toString(16)) == a_hex);
    },

    'B': function() {
      var B = srp.getB(v, g, b, N, ALG);
      assert(pad(B.toString(16)) == B_hex);
    },

    'A': function() {
      var A = srp.getA(g, a, N);
      assert(pad(A.toString(16)) == A_hex);
    },

    'u': function() {
      var A = bigint(A_hex, 16);
      var B = bigint(B_hex, 16);
      var u = srp.getu(A, B, N, ALG);
      assert(u.toString(16) == u_hex);
    },

    'secrets': {
      'client': {
        topic: function() {
          var B = bigint(B_hex, 16);
          return srp.client_getS(s, I, P_stretch, N, g, a, B, ALG);
        },

        'S': function(S) {
          assert(pad(S.toString(16)) == S_hex);
        },

        'K': function(S) {
          assert(srp.getK(S, ALG).toString(16) == K_hex);
        }
        
      },

      'server': {
        topic: function() {
          var A = bigint(A_hex, 16);
          return srp.server_getS(s, v, N, g, A, b, ALG);
        },

        'S': function(S) {
          assert(pad(S.toString(16)) == S_hex);
        },

        'K': function(S) {
          assert(srp.getK(S, ALG).toString(16) == K_hex);
        }
      }
    }
  }
})

.export(module);
