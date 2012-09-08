#SRP - Secure Remote Password

Implementation of the [SRP Authentication and Key Exchange System](http://tools.ietf.org/html/rfc2945).

http://tools.ietf.org/html/rfc5054

Work in progress.

Want to support:

- [done] srp function library that passes http://tools.ietf.org/html/rfc5054#appendix-B tests
- srp server
- javascript browser client

##Initial Setup

Carol the Client wants to share messages with Steve the server.

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

##Message Protocol

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

##Glossary of Terms

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

##License

MIT