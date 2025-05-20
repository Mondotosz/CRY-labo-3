```sage
sage: p = random_prime(2**256)
sage: F = Integers(p)
sage: a = F(16)
sage: a
16
sage: type(a)
<class 'sage.rings.finite_rings.integer_mod.IntegerMod_gmp'>
sage: a.sqrt()
4
sage: a.sqrt(all=True)
[4,
 41089807506753976972057093589164565856198282096436787468751966415589684920029]
```
