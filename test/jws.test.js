/*global process*/
const Buffer = require('buffer').Buffer;
const fs = require('fs');
const test = require('tape');
const jws = require('..');

function readfile(path) {
  return fs.readFileSync(__dirname + '/' + path).toString();
}

function readstream(path) {
  return fs.createReadStream(__dirname + '/' + path);
}

const rsaPrivateKey = readfile('rsa-private.pem');
const rsaPublicKey = readfile('rsa-public.pem');
const rsaWrongPublicKey = readfile('rsa-wrong-public.pem');
const ecdsaPrivateKey = {
  '256': readfile('ec256-private.pem'),
  '384': readfile('ec384-private.pem'),
  '512': readfile('ec512-private.pem'),
};
const ecdsaPublicKey = {
  '256': readfile('ec256-public.pem'),
  '384': readfile('ec384-public.pem'),
  '512': readfile('ec512-public.pem'),
};
const ecdsaWrongPublicKey = {
  '256': readfile('ec256-wrong-public.pem'),
  '384': readfile('ec384-wrong-public.pem'),
  '512': readfile('ec512-wrong-public.pem'),
};

const BITS = ['256', '384', '512'];
const CURVES = {
  '256': '256',
  '384': '384',
  '512': '521',
};

BITS.forEach(function (bits) {
  test('HMAC using SHA-'+bits+' hash algorithm', function (t) {
    const alg = 'HS'+bits;
    const header = { alg: alg, typ: 'JWT' };
    const payload = {name: 'oh hey', value: ['one', 2, 3]};
    const secret = 'sup';
    const jwsObj = jws.sign({
      header: header,
      payload: payload,
      secret: secret
    });
    const parts = jws.decode(jwsObj);
    t.ok(jws.verify(jwsObj, alg, secret), 'should verify');
    t.notOk(jws.verify(jwsObj, alg, 'something else'), 'should not verify with non-matching secret');
    t.notOk(jws.verify(jwsObj, 'RS'+bits, secret), 'should not verify with non-matching algorithm');
    t.same(parts.payload, payload, 'should match payload');
    t.same(parts.header, header, 'should match header');
    t.end();
  });
});

BITS.forEach(function (bits) {
  test('RSASSA using SHA-'+bits+' hash algorithm', function (t) {
    const alg = 'RS'+bits;
    const header = { alg: alg };
    const payload = {name: 'oh hey', value: ['one', 2, 3]};
    const privateKey = rsaPrivateKey;
    const publicKey = rsaPublicKey;
    const wrongPublicKey = rsaWrongPublicKey;
    const jwsObj = jws.sign({
      header: header,
      payload: payload,
      privateKey: privateKey
    });
    const parts = jws.decode(jwsObj, { json: true });
    t.ok(jws.verify(jwsObj, alg, publicKey), 'should verify');
    t.notOk(jws.verify(jwsObj, alg, wrongPublicKey), 'should not verify with non-matching public key');
    t.notOk(jws.verify(jwsObj, 'HS'+bits, publicKey), 'should not verify with non-matching algorithm');
    t.same(parts.payload, payload, 'should match payload');
    t.same(parts.header, header, 'should match header');
    t.end();
  });
});

BITS.forEach(function (bits) {
  const curve = CURVES[bits];
  test('ECDSA using P-'+curve+' curve and SHA-'+bits+' hash algorithm', function (t) {
    const alg = 'ES'+bits;
    const header = { alg: alg };
    const payload = 'oh hey';
    const privateKey = ecdsaPrivateKey['256'];
    const publicKey = ecdsaPublicKey['256'];
    const wrongPublicKey = ecdsaWrongPublicKey['256'];
    const jwsObj = jws.sign({
      header: header,
      payload: payload,
      privateKey: privateKey
    });
    const parts = jws.decode(jwsObj);
    t.ok(jws.verify(jwsObj, alg, publicKey), 'should verify');
    t.notOk(jws.verify(jwsObj, alg, wrongPublicKey), 'should not verify with non-matching public key');
    t.notOk(jws.verify(jwsObj, 'HS'+bits, publicKey), 'should not verify with non-matching algorithm');
    t.same(parts.payload, payload, 'should match payload');
    t.same(parts.header, header, 'should match header');
    t.end();
  });
});

test('No digital signature or MAC value included', function (t) {
  const alg = 'none';
  const header = { alg: alg };
  const payload = 'oh hey';
  const jwsObj = jws.sign({
    header: header,
    payload: payload,
  });
  const parts = jws.decode(jwsObj);
  t.ok(jws.verify(jwsObj, alg), 'should verify');
  t.ok(jws.verify(jwsObj, alg, 'anything'), 'should still verify');
  t.notOk(jws.verify(jwsObj, 'HS256', 'anything'), 'should not verify with non-matching algorithm');
  t.same(parts.payload, payload, 'should match payload');
  t.same(parts.header, header, 'should match header');
  t.end();
});

test('Streaming sign: HMAC', function (t) {
  const dataStream = readstream('data.txt');
  const secret = 'shhhhh';
  const sig = jws.createSign({
    header: { alg: 'HS256' },
    secret: secret
  });
  dataStream.pipe(sig.payload);
  sig.on('done', function (signature) {
    t.ok(jws.verify(signature, 'HS256', secret), 'should verify');
    t.end();
  });
});

test('Streaming sign: RSA', function (t) {
  const dataStream = readstream('data.txt');
  const privateKeyStream = readstream('rsa-private.pem');
  const publicKey = rsaPublicKey;
  const wrongPublicKey = rsaWrongPublicKey;
  const sig = jws.createSign({
    header: { alg: 'RS256' },
  });
  dataStream.pipe(sig.payload);

  process.nextTick(function () {
    privateKeyStream.pipe(sig.key);
  });

  sig.on('done', function (signature) {
    t.ok(jws.verify(signature, 'RS256', publicKey), 'should verify');
    t.notOk(jws.verify(signature, 'RS256', wrongPublicKey), 'should not verify');
    t.same(jws.decode(signature).payload, readfile('data.txt'), 'got all the data');
    t.end();
  });
});

test('Streaming sign: RSA, predefined streams', function (t) {
  const dataStream = readstream('data.txt');
  const privateKeyStream = readstream('rsa-private.pem');
  const publicKey = rsaPublicKey;
  const wrongPublicKey = rsaWrongPublicKey;
  const sig = jws.createSign({
    header: { alg: 'RS256' },
    payload: dataStream,
    privateKey: privateKeyStream
  });
  sig.on('done', function (signature) {
    t.ok(jws.verify(signature, 'RS256', publicKey), 'should verify');
    t.notOk(jws.verify(signature, 'RS256', wrongPublicKey), 'should not verify');
    t.same(jws.decode(signature).payload, readfile('data.txt'), 'got all the data');
    t.end();
  });
});

test('Streaming verify: ECDSA', function (t) {
  const dataStream = readstream('data.txt');
  const privateKeyStream = readstream('ec512-private.pem');
  const publicKeyStream = readstream('ec512-public.pem');
  const sigStream = jws.createSign({
    header: { alg: 'ES512' },
    payload: dataStream,
    privateKey: privateKeyStream
  });
  const verifier = jws.createVerify({algorithm: 'ES512'});
  sigStream.pipe(verifier.signature);
  publicKeyStream.pipe(verifier.key);
  verifier.on('done', function (valid) {
    t.ok(valid, 'should verify');
    t.end();
  });
});

test('Streaming verify: ECDSA, with invalid key', function (t) {
  const dataStream = readstream('data.txt');
  const privateKeyStream = readstream('ec512-private.pem');
  const publicKeyStream = readstream('ec512-wrong-public.pem');
  const sigStream = jws.createSign({
    header: { alg: 'ES512' },
    payload: dataStream,
    privateKey: privateKeyStream
  });
  const verifier = jws.createVerify({
    algorithm: 'ES512',
    signature: sigStream,
    publicKey: publicKeyStream,
  });
  verifier.on('done', function (valid) {
    t.notOk(valid, 'should not verify');
    t.end();
  });
});

test('jws.decode: not a jws signature', function (t) {
  t.same(jws.decode('some garbage string'), null);
  t.same(jws.decode('http://sub.domain.org'), null);
  t.end();
});

test('jws.decode: with a bogus header ', function (t) {
  const header = Buffer('oh hei').toString('base64');
  const payload = Buffer('sup').toString('base64');
  const sig = header + '.' + payload + '.';
  const parts = jws.decode(sig);
  t.same(parts, null);
  t.end();
});

test('jws.verify: missing or invalid algorithm', function (t) {
  const header = Buffer('{"something":"not an algo"}').toString('base64');
  const payload = Buffer('sup').toString('base64');
  const sig = header + '.' + payload + '.';
  try { jws.verify(sig) }
  catch (e) {
    t.same(e.code, 'MISSING_ALGORITHM');
  }
  try { jws.verify(sig, 'whatever') }
  catch (e) {
    t.ok(e.message.match('"whatever" is not a valid algorithm.'));
  }
  t.end();
});

test('jws.verify: algorithm is required, not taken from the header', function (t) {
  const jwsObj = jws.sign({
    header: { alg: 'HS256' },
    payload: 'oh hey',
    secret: 'shhhhh'
  });
  var code = null;
  try { jws.verify(jwsObj, null, 'shhhhh') }
  catch (e) { code = e.code }
  t.same(code, 'MISSING_ALGORITHM', 'should throw when no algorithm is given');
  t.end();
});

test('jws.verify: HS256 token forged with the RSA public key', function (t) {
  const legit = jws.sign({
    header: { alg: 'RS256' },
    payload: 'oh hey',
    privateKey: rsaPrivateKey
  });
  const forged = jws.sign({
    header: { alg: 'HS256' },
    payload: 'forged',
    secret: rsaPublicKey
  });
  t.ok(jws.verify(legit, 'RS256', rsaPublicKey), 'should verify a genuine RS256 token');
  t.notOk(jws.verify(forged, 'RS256', rsaPublicKey), 'should not verify a token whose header switches to HS256');
  t.end();
});

test('jws.verify: unsigned token with alg none', function (t) {
  const forged = jws.sign({
    header: { alg: 'none' },
    payload: 'forged'
  });
  t.notOk(jws.verify(forged, 'RS256', rsaPublicKey), 'should not verify an unsigned token as RS256');
  t.notOk(jws.verify(forged, 'HS256', 'shhhhh'), 'should not verify an unsigned token as HS256');
  t.end();
});

test('jws.verify: algorithm must match exactly', function (t) {
  const forged = jws.sign({
    header: { alg: 'none' },
    payload: 'forged'
  });
  var accepted = null;
  var error = null;
  try { accepted = jws.verify(forged, 'mynonesecret') }
  catch (e) { error = e }
  t.same(accepted, null, 'should not accept an unsigned token for a secret containing "none"');
  t.ok(error instanceof TypeError, 'should throw a TypeError for "mynonesecret"');
  t.ok(error && error.message.match('"mynonesecret" is not a valid algorithm.'), 'should report "mynonesecret" as an invalid algorithm');

  const jwsObj = jws.sign({
    header: { alg: 'HS256' },
    payload: 'oh hey',
    secret: 'shhhhh'
  });
  error = null;
  try { jws.verify(jwsObj, 'hs256', 'shhhhh') }
  catch (e) { error = e }
  t.ok(error instanceof TypeError, 'should throw a TypeError for lowercase "hs256"');
  t.ok(error && error.message.match('"hs256" is not a valid algorithm.'), 'should report "hs256" as an invalid algorithm');
  t.end();
});

test('Streaming verify: HS256 token forged with the RSA public key', function (t) {
  const forged = jws.sign({
    header: { alg: 'HS256' },
    payload: 'forged',
    secret: rsaPublicKey
  });
  const verifier = jws.createVerify({
    algorithm: 'RS256',
    signature: forged,
    publicKey: rsaPublicKey,
  });
  verifier.on('done', function (valid) {
    t.notOk(valid, 'should not verify a token whose header switches to HS256');
    t.end();
  });
});

test('Streaming verify: unsigned token with alg none', function (t) {
  const forged = jws.sign({
    header: { alg: 'none' },
    payload: 'forged'
  });
  const verifier = jws.createVerify({
    algorithm: 'RS256',
    signature: forged,
    publicKey: rsaPublicKey,
  });
  verifier.on('done', function (valid) {
    t.notOk(valid, 'should not verify an unsigned token as RS256');
    t.end();
  });
});


test('jws.isValid', function (t) {
  const valid = jws.sign({ header: { alg: 'hs256' }, payload: 'hi', secret: 'shhh' });
  const invalid = (function(){
    const header = Buffer('oh hei').toString('base64');
    const payload = Buffer('sup').toString('base64');
    return header + '.' + payload + '.';
  })();
  t.same(jws.isValid('http://sub.domain.org'), false);
  t.same(jws.isValid(invalid), false);
  t.same(jws.isValid(valid), true);
  t.end();
});

test('Streaming sign: HMAC with empty secret buffer', function (t) {
  const dataStream = readstream('data.txt');
  const secret = new Buffer(0);
  const sig = jws.createSign({
    header: { alg: 'HS256' },
    secret: secret
  });
  dataStream.pipe(sig.payload);
  sig.on('done', function (signature) {
    t.ok(jws.verify(signature, 'HS256', secret), 'should verify');
    t.end();
  }).sign();
});

test('Streaming sign: HMAC with empty secret string', function (t) {
  const dataStream = readstream('data.txt');
  const secret = '';
  const sig = jws.createSign({
    header: { alg: 'HS256' },
    secret: secret
  });
  dataStream.pipe(sig.payload);
  sig.on('done', function (signature) {
    t.ok(jws.verify(signature, 'HS256', secret), 'should verify');
    t.end();
  }).sign();
});

test('Streaming sign: HMAC with undefined secret', function (t) {
  try {
    jws.createSign({
      header: { alg: 'HS256' },
      secret: undefined
    });
    t.fail('should have errored');
    t.end();
  } catch (error) {
    t.equal(error.name, 'TypeError');
    t.equal(error.message, 'secret must be a string or buffer or a KeyObject');
    t.end();
  }
});

test('Streaming sign: HMAC with null secret', function (t) {
  try {
    jws.createSign({
      header: { alg: 'HS256' },
      secret: null
    });
    t.fail('should have errored');
    t.end();
  } catch (error) {
    t.equal(error.name, 'TypeError');
    t.equal(error.message, 'secret must be a string or buffer or a KeyObject');
    t.end();
  }
});

test('Streaming verify: HMAC with empty secret buffer', function (t) {
  const secret = new Buffer(0);
  jws.createVerify({
    signature: 'eyJhbGciOiJIUzI1NiJ9.b25lLCB0d28sIHRocmVlCg.V1oQ0aq6FgAoe7C2TORtYpQAbYzJoFNFZlJkTlF1e60',
    algorithm: 'HS256',
    secret: secret
  }).on('done', function (valid, decoded) {
    t.true(valid);
    t.same(decoded.payload, readfile('data.txt'));
    t.end();
  }).verify();
});

test('Streaming verify: HMAC with empty secret string', function (t) {
  const secret = '';
  jws.createVerify({
    signature: 'eyJhbGciOiJIUzI1NiJ9.b25lLCB0d28sIHRocmVlCg.V1oQ0aq6FgAoe7C2TORtYpQAbYzJoFNFZlJkTlF1e60',
    algorithm: 'HS256',
    secret: secret
  }).on('done', function (valid, decoded) {
    t.true(valid);
    t.same(decoded.payload, readfile('data.txt'));
    t.end();
  }).verify();
});

test('Streaming verify: HMAC with undefined secret', function (t) {
  try {
    jws.createVerify({
      signature: 'eyJhbGciOiJIUzI1NiJ9.b25lLCB0d28sIHRocmVlCg.V1oQ0aq6FgAoe7C2TORtYpQAbYzJoFNFZlJkTlF1e60',
      algorithm: 'HS256',
      secret: undefined
    });
    t.fail('should have errored');
    t.end();
  } catch (error) {
    t.equal(error.name, 'TypeError');
    t.equal(error.message, 'secret must be a string or buffer or a KeyObject');
    t.end();
  }
});

test('Streaming verify: HMAC with null secret', function (t) {
  try {
    jws.createVerify({
      signature: 'eyJhbGciOiJIUzI1NiJ9.b25lLCB0d28sIHRocmVlCg.V1oQ0aq6FgAoe7C2TORtYpQAbYzJoFNFZlJkTlF1e60',
      algorithm: 'HS256',
      secret: null
    });
    t.fail('should have errored');
    t.end();
  } catch (error) {
    t.equal(error.name, 'TypeError');
    t.equal(error.message, 'secret must be a string or buffer or a KeyObject');
    t.end();
  }
});

test('Streaming verify: HMAC token forged with an empty key when the secret lookup misses', function (t) {
  const keys = { 'known-kid': 'shhhhh' };
  const forged = jws.sign({
    header: { alg: 'HS256', kid: 'unknown-kid' },
    payload: 'forged',
    secret: new Buffer(0)
  });
  const secret = keys[jws.decode(forged).header.kid];
  ['secret', 'publicKey', 'key'].forEach(function (name) {
    const opts = { signature: forged, algorithm: 'HS256' };
    opts[name] = secret;
    var valid = null;
    var error = null;
    try { valid = jws.createVerify(opts).verify() }
    catch (e) { error = e }
    t.notOk(valid, 'should not verify a token signed with an empty key (' + name + ')');
    t.ok(error instanceof TypeError, 'should throw a TypeError when the ' + name + ' is missing');
  });
  t.end();
});

test('Streaming sign: HMAC with a missing secret does not sign with an empty key', function (t) {
  var signature = null;
  var error = null;
  try {
    signature = jws.createSign({
      header: { alg: 'hs256' },
      payload: 'oh hey',
      privateKey: undefined
    }).sign();
  }
  catch (e) { error = e }
  t.same(signature, null, 'should not produce a signature for a lowercase hs256 header');
  t.ok(error instanceof TypeError, 'should throw a TypeError when the secret is missing');
  t.end();
});
