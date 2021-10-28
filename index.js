// @ts-nocheck
const base45 = require('base45');
const cbor = require('cbor');
const cose = require('cose-js');
const fs = require('fs');
const zlib = require('zlib');
const rs = require('jsrsasign');
const express = require('express');
const app = express();
var cors = require('cors')
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

let keys = JSON.parse(fs.readFileSync('keys.json'));
let certs = JSON.parse(fs.readFileSync('updates.json'));
let trustListLastUpdate;

app.post('/verify', (req, res) => {
    console.log(req.body);
    let cert = req.body.cert;
    cert = cert.slice(4);
    const base45decoded = base45.decode(cert);
    const _coseRaw = zlib.inflateSync(base45decoded);
    let [headers1, headers2, cborPayload, signature] = cbor.decodeFirstSync(_coseRaw).value;
    const kid = cbor.decodeFirstSync(headers1).get(4).toString('base64');
    const jsonCBOR = cbor.decodeFirstSync(cborPayload);
    const _payload = jsonCBOR.get(-260).get(1);

    try {
        let verifier;
    if (req.body.signcert) {
        verifier = checkWithCertificate(req.body.signcert);
    } else {
        verifier = checkSignature(kid)
    }

    if (verifier) {
        cose.sign.verify(_coseRaw, verifier).then((buf) => {
            res.send({valid: true, data:cbor.decodeFirstSync(buf).get(-260).get(1)});
        });
    } 
    } catch (error) {
        console.log(error);
        res.send({valid: false, reason: error.message});
    }
    
});

app.get('/lastUpdate', (req, res) => {
    res.send(trustListLastUpdate);
}); 

function updateTrustlist() {
    keys = JSON.parse(fs.readFileSync('keys.json'));
    certs = JSON.parse(fs.readFileSync('updates.json'));
    trustListLastUpdate = new Date();
}



function checkWithCertificate(cert) {
    if (!cert.startsWith('-----BEGIN CERTIFICATE-----')) {
        cert = '-----BEGIN CERTIFICATE-----' + cert + '-----END CERTIFICATE-----';
    }
    const key = rs.KEYUTIL.getKey(cert);
    if (key.type === 'EC') {
        return key.getPublicKeyXYHex();
    } else if (key.type === 'RSA') {
        const jwk = rs.KEYUTIL.getJWKFromKey(key);
        return {
            key: {
                n: Buffer.from(jwk.n, 'base64'),
                e: Buffer.from(jwk.e, 'base64')
            }

        };
    } else {
        throw new Error('Certificate not supported');
    }
}

function checkSignature(kid) {
    console.log(kid);
    if (!checkIfKeyIsActive(kid)) throw new Error('No active key found');
    current_key = certs['certs'].find((it) => it['keyId'] == kid);
    return {
        key: {
            n: Buffer.from(current_key['n'], 'base64'),
            e: Buffer.from(current_key['e'], 'base64')
        }
    };
}

function checkIfKeyIsActive(kid) {
    return keys['activeKeyIds'].indexOf(kid) > -1;
}

app.listen(PORT, function() {
    console.log(`Server running at on port ${PORT}`);
    updateTrustlist();
 })
