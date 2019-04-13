# z-dsa
Z Digital Signature Algorithm - Hash Based

One time signature schema.

INSPIRAITON:
Shamir's secret threshold and Lamport signature schema.

GOAL
Keep security while reducing keys and signature size.

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
