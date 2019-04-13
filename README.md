# z-dsa
Z Digital Signature Algorithm - Hash Based

One time signature schema.

INSPIRAITON:
Shamir's secret threshold and Lamport signature schema.

GOAL:Keep security while reducing keys and signature size.

WARNING: Do not use this in production yet. It is not tested enough.
I am not an expert, but I would like to see opinions if experienced persons about my work.



INSTALL
```javascript
npm i z-dsa
```
Example
```javascript
const zdsa = require("z-dsa");
const crypto = require("crypto");
var keys = zdsa.keyPairNew();
var msg = crypto.randomBytes(32);
var signature = zdsa.sign(keys.private, msg);
console.log("zdsa",keys.private.length,keys.public.length,signature.length);
console.log(zdsa.verify(keys.public, msg, signature));
```

How it works.

We need at least one hash function or two different.

First hash function should be a strongerone, second can be weak as even md5.

First hash function will be used to generate signature, while second is used to generate public key.

I will show example with a minimum security.

We will define few constants.

CELL_SIZE_L  -> as 32  // size of first hash function output in bytes like sha256

CELL_SIZE_S ->  as 16 // size of second hash function output in bytes like md5

HASH_COUNT -> as 64  //  number of hashes used to generate private key

so
PRIVATE_KEY_BYTES = CELL_SIZE_L*HASH_COUNT /// size of private key in bytes - 2048 for our case

PUBLIC_KEY_BYTES = CELL_SIZE_S*HASH_COUNT /// size of public key in bytes - 1024 for our case

SIGNATURE_BYTES = CELL_SIZE_L * CELL_SIZE_L /// size of signature in bytes - 1024 for our case

SHARE_COEFFICIENT= 22 // percent of minimum shares in percent

MIN_SHARE_COUNT = MIN_SHARE_COUNT = round(HASH_COUNT/100*SHARE_COEFFICIENT) - 14 in our case



KEY CREATION
Allice will generate random bytes (Nonce) of CELL_SIZE_L size and will generate Shamir's threshold share 

with HASH_COUNT shares and MIN_SHARE_COUNT threshold.

Each share must be CELL_SIZE_L+1 size in bytes.

To create private key from shares we exclude first byte of each share and join all shares together.

That is Allice private key.

To generate public key we hash each share from private key with second hash function together with nonce and joing them together.

That is Allice public key and she can share it with the world.



SIGNATURE CREATION

We will call first hash function as HL.

To create signature we need message M which size can be up to CELL_SIZE_L size in bytes and Allice private key.

She will hash message M with HL and iterate over each byte then MOD byte value with HASH_COUNT.

HM = HL(M)

foreach HM as B 

I = B MOD HASH_COUNT

She will choose share from private key by calculated index I to insert into signature.

That is her signature.



VERIFYING SIGNATURE

We will call second hash function as HS.

Bob would like to verify the signature.

Hi will need message M, Allice public key Pk and Allice signature S.

First hi will iterate over shares in signature to collect MIN_SHARE_COUNT different shares.

Then Bob will recover Nonce with collected shares if hi has rigth shares in signature.

Then hi will hash message in the same way like on signature creation

HM = HL(M)

foreach HM as NUM=>B 

I = B MOD HASH_COUNT

NUM is index of HM byte also index of signature share.

I is index of public key part where part Pk[I] = HS(S[NUM]|Nonce)

So if Bob realize that all Pk[I] = HS(S[NUM]|Nonce) equals, signature is valid.



Hope I was expalined good enough. Since I do better with code then with explaining what codes do.













