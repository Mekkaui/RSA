'use strict';

var fs = require('fs');
var ursa = require('ursa');
var msg;
var sig;
var enc;
var rcv;

// Bob has his private and Alice's public key
var privkeyBob = ursa.createPrivateKey(fs.readFileSync('private.pem'));
var pubkeyAlice = ursa.createPublicKey(fs.readFileSync('public.pem'));

// Alice has her private and Bob's public key
var privkeyAlice = ursa.createPrivateKey(fs.readFileSync('private.pem'));
var pubkeyBob = ursa.createPublicKey(fs.readFileSync('public.pem'));

msg = "IT’S A SECRET TO EVERYBODY.";

console.log('Encrypt with Alice Public; Sign with Bob Private');
enc = pubkeyAlice.encrypt(msg, 'utf8', 'base64');
sig = privkeyBob.hashAndSign('sha256', msg, 'utf8', 'base64');
console.log('encrypted', enc, '\n');
console.log('signed', sig, '\n');

console.log('Decrypt with Alice Private; Verify with Bob Public');
rcv = privkeyAlice.decrypt(enc, 'base64', 'utf8');
if (msg !== rcv) {
  throw new Error("invalid decrypt");
}
rcv = new Buffer(rcv).toString('base64');
if (!pubkeyBob.hashAndVerify('sha256', rcv, sig, 'base64')) {
  throw new Error("invalid signature");
}
console.log('decrypted', msg, '\n');
