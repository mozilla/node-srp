#SRP - Secure Remote Password

Implementation of the [SRP Authentication and Key Exchange System](http://tools.ietf.org/html/rfc2945).

http://tools.ietf.org/html/rfc5054

Work in progress.

Want to support:

- [done] srp function library that passes http://tools.ietf.org/html/rfc5054#appendix-B tests
- srp server
- javascript browser client

##Protocol Flow

Protocol flow:

```
         Client                       Server

1.                     --  I  ->   lookup s, v
2.  x = H(s, I, P)     <-  s  --
3.  A = g^a            --  A  ->
4.                     <- B,u --   B = v + g^b
5.  S = (B-g^w)^(a+ux)             S = (Av^u)^b
6.  M1 = H(A, B, S)    --  M1 ->   verify M1
7.  verify M2          <-  M2 --   M2 = H(A, M1, S)
8.  K = H(S)                       K = H(S)
```

H
##License

MIT