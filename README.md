#SRP - Secure Remote Password

This is a work in progress.  I'm trying to figure some stuff out with it.

Implementation of the [SRP Authentication and Key Exchange
System](http://tools.ietf.org/html/rfc2945) and protocols in [Secure
Remote Password (SRP) Protocol for TLS
Authentication](http://tools.ietf.org/html/rfc5054) (including the
test vectors in the latter).

The goals are to provide at a minimum:

- [done] SRP function library that passes [RFC 5054 tests](http://tools.ietf.org/html/rfc5054#appendix-B)
- [done] SRP server
- [done] SRP test client
- SRP client lib for Node.js
- JavaScript browser client

Additionally, I would like the API to provide:

- A way to bind messages of intent to the session key in a way that
  preserves integrity, confidentiality, and protects against replay
  attacks.

##Prerequisites

[GNU libgmp](http://gmplib.org/) for those big big numbers.

- debian: `libgmp3-dev`
- brew: `gmp`

##Installation

`git clone` this archive.

In the `node-srp` dir, run `npm install`.

##Tests

In the `node-srp` dir, run `npm test`.

##Protocol

###Initial Setup

Carol the Client wants to share messages with Steve the server.
Before this can happen, they need to perform a one-time setup step.

Carol and Steve agree on a large random number `N` and a generator
`g`.  These can be published in advance or better yet hard-coded in
their implementations.  They also agree on a cryptographic hashing
function `H`.

Carol establishes a password and remembers it well.  She the generates
some random salt, `s`, and compputes the verifier `v` as `g ^ H(s |
H(I | ':' | P)) % N`, where `I` is Carol's identity, and `|` denotes
concatenation.

Carol then sends Steve `I`, `s`, and `v`.  She also sends the size of
`N` and the name of the hashing algorithm she has chosen.

Steve stores `I`, `s`, and `v`.  Carol remembers `P`.  This sequence
is performed once, after which Carol and Steve can use the SRP
protocol to share messages.

###Message Protocol

First, Carol generates an ephemeral private key `a`.  She computes the
public key `A` as `g^a % N`.  She sends Steve `I` and `A`.

Client sends `I`, `A`.

Steve looks up `v` and `s`.  Steve generates an ephemeral private key
`b` and computes the public key `B` as `k * v + g^b % N`, where `k` is
`H(PAD(g))`.  (`PAD` designates a function that left-pads a byte
string with zeroes until it is the same size as `N`.)  Steve sends `s`
and `B`.

Server replies with `s` and `B`.

Both now compute the scrambling parameter `u` as `u = H(PAD(A) | PAD(B))`.

Now both Carol and Steve have the parameters they need to compute
their session key, `S`.

For Carol, the formula is:

```
S_client = (B - k * g^x) ^ (a + u * x)
```

For Steve, the formula is:

```
S_server = (A * v ^ u) ^ b
```

They both now compute the shared session key, `K`, as `H(S)`.  (The
hash is taken to obscure any structure that may be visible in `S`.)

Now Carol and Steve must convince each other that their values for `K`
match.  Here, Carol hashes and hashes again her session key and sends
it to Steve.  If he gets the same result when hashing his session key
twice, he hashes his session key once and sends it back to Carol, who
can check if she wishes that she gets the same value.

###Glossary of Terms

`N` a large prime number

`g` a generator

`H` a secure hashing function

`|` the concatenation operator

`PAD` a function that left-pads a block of bytes with zeroes until it is the same length as `N`

`I` the identity of the client (a string)

`P` the password of the client (a string)

`s` some random salt (a string)

`v` the verifier

`k` a multiplier

`u` a scrambling parameter

`a` an ephemeral private key known to the client

`A` the public key from `a`

`b` an ephemeral private key known to the server

`B` the public key from `b`

`x` an intermediate value, `H(s | H(I | ":" | P))`

`S` the session key

`K` a hash of the session key shared between client and server

##Resources

- [The Stanford SRP Homepage](http://srp.stanford.edu/)
- RFC 2945: [The SRP Authentication and Key Exchange System](http://tools.ietf.org/html/rfc2945)
- RFC 5054: [Using the Secure Remote Password (SRP) Protocol for TLS Authentication](http://tools.ietf.org/html/rfc5054)
- Wikipedia: [The Secure Remote Password protocol](http://en.wikipedia.org/wiki/Secure_Remote_Password_protocol)

##License

MIT