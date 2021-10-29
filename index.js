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
const https = require('https');
app.use(express.json());

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*')
    res.header('Access-Control-Allow-Headers', [
        'Accept',
        'Authorization',
        'Content-Type',
        'Origin',
        'X-Requested-With'
    ].join(', '))
    res.header('Access-Control-Allow-Methods', [
        'DELETE',
        'GET',
        'HEAD',
        'OPTIONS',
        'PATCH',
        'POST',
        'PUT'
    ].join(', '))
    next()
});

app.use(cors());
let trustListLastUpdate = {'keys': -1, 'updates': -1};

app.post('/verify', (req, res) => {
    console.log(req.body);
    let cert = req.body.cert;
    const isLight = cert.startsWith('LT');
    cert = cert.slice(4);
    const base45decoded = base45.decode(cert);
    const _coseRaw = zlib.inflateSync(base45decoded);
    let [headers1, headers2, cborPayload, signature] = cbor.decodeFirstSync(_coseRaw).value;
    const kid = cbor.decodeFirstSync(headers1).get(4).toString('base64');
    const jsonCBOR = cbor.decodeFirstSync(cborPayload);
    const _payload = isLight ? jsonCBOR.get(-250).get(1) : jsonCBOR.get(-260).get(1);

    try {
        let verifier;
    if (req.body.signcert) {
        verifier = checkWithCertificate(req.body.signcert);
    } else {
        verifier = checkSignature(kid)
    }

    if (verifier) {
        cose.sign.verify(_coseRaw, verifier).then((buf) => {
            data = cbor.decodeFirstSync(buf);
            body = checkRulesAndCreateObject(data)
            res.send(body);
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
    updateKeys();
    updateUpdates();     
    
    trustListLastUpdate = new Date();
}

function updateKeys() {
    let req = https.request({
        hostname: 'www.cc.bit.admin.ch',
        path: '/trust/v1/keys/list',
        method: 'GET',
        headers: {
            'Accept': 'application/json',
            'Authorization': 'Bearer 0795dc8b-d8d0-4313-abf2-510b12d50939'
        },
    }, (res) => {
        let received = '';
        res.on('data', function (chunk) {
            received += chunk; 
        });

        res.on('end', () => {
            fs.writeFile('keys.json', received, (err) => {
                if (err) return;
                certs = JSON.parse(fs.readFileSync('updates.json'));
                trustListLastUpdate.updates = new Date();
            });
        });
    });
    req.on('error', function(e) {
        console.log('problem with request: ' + e.message);
    });
    req.end();
}

function updateUpdates() {
    let req = https.request({
        hostname: 'www.cc.bit.admin.ch',
        path: '/trust/v1/keys/updates?certFormat=ANDROID',
        method: 'GET',
        headers: {
            'Accept': 'application/json',
            'Authorization': 'Bearer 0795dc8b-d8d0-4313-abf2-510b12d50939'
        },
    }, (res) => {
        let received = '';
        res.on('data', function (chunk) {
            received += chunk; 
        });

        res.on('end', () => {
            fs.writeFile('updates.json', received, (err) => {
                if (err) return;
                certs = JSON.parse(fs.readFileSync('updates.json'));
                trustListLastUpdate.updates = new Date();
            });
        });
    });
    req.on('error', function(e) {
        console.log('problem with request: ' + e.message);
    });
    req.end();   
}

function checkRulesAndCreateObject(data) {
    const isLight = data.get(-250) ? true : false;
    if (isLight) {
        const cert_data = data.get(-250).get(1);
        
        return {type: 'L', iss: data.get(1), iss_at: data.get(6)*1000, data: cert_data, valid: Date.now() < data.get(4)*1000}
    }
    const cert_data =  data.get(-260).get(1);
    const type = cert_data.v ? 'V' : cert_data.t ? 'T' : 'R';
    const iss = data.get(1);
    const iss_at = data.get(6)*1000;
    let valid = true;

    if (type === 'V'){
        validateVacc(cert_data.v[0]);
    } else if (type === 'T') {
        validateTest(cert_data.t[0]);
    } else {
        validateRec(cert_data.r[0]);
    }

    return {type, iss, iss_at, valid, data: cert_data}
}

function validateVacc(cert_data) {
    // Version 1.4 (https://ec.europa.eu/health/sites/default/files/ehealth/docs/digital-green-value-sets_en.pdf)
    let vacc_date = cert_data.dt ? new Date(cert_data.dt*1000) : new Date(0);
    valid = 
        (cert_data.tg && cert_data.tg === '840539006') && // Vaccinated against covid
        (cert_data.vp && ['1119305005', '1119349007', 'J07BX03'].indexOf(cert_data.vp) > -1) && //Type of the vaccine or prophylaxis used
        (cert_data.mp && cert_data.ma ) && // check fields are there, validate content is too much for this project
        (cert_data.dn && cert_data.sd && cert_data.dn === cert_data.sd) && // All doses received
        (vacc_date.setFullYear(vacc_date.getFullYear() + 1) > Date.now()); // 1 Year
    return valid;
}

function validateTest(cert_data) {
    let test_time = cert_data.sc ? new Date(cert_data.sc*1000) : new Date(0);
    valid = 
        (cert_data.tg && cert_data.tg === '840539006') && 
        (cert_data.tt && ['LP6464-4', 'LP217198-3'].indexOf(cert_data.tt) > -1) && 
        (new Date() - test_time <  (cert_data.tt === 'LP6464-4' ? 72*60*60*1000 : 48*60*60*1000)) && 
        (cert_data.tr && cert_data.tr === '260415000') &&
        (vacc_date.setFullYear(vacc_date.getFullYear() + 1) > Date.now()); 
    return valid;
}

function validateRec(cert_data) {
    let test_time = cert_data.fr ? new Date(cert_data.fr*1000) : new Date(0);
    let time_diff = new Date() - test_time;
    valid = 
        (cert_data.tg && cert_data.tg === '840539006') && 
        (time_diff > 11*24*60*60*1000 && time_diff < 180*24*60*60*1000) && 
        (cert_data.is && cert_data.df && cert_data.du && cert_data.ci);
    return valid;
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
    if (current_key['n']) {
        return {
            key: {
                n: Buffer.from(current_key['n'], 'base64'),
                e: Buffer.from(current_key['e'], 'base64')
            }
        };
    } else {
        return {
            key: {
                x: Buffer.from(current_key['x'], 'base64'),
                y: Buffer.from(current_key['y'], 'base64')
            }
        };
    }
    
}

function checkIfKeyIsActive(kid) {
    return keys['activeKeyIds'].indexOf(kid) > -1;
}

app.listen(PORT, function() {
    console.log(`Server running at on port ${PORT}`);
    keys = JSON.parse(fs.readFileSync('keys.json'));
    certs = JSON.parse(fs.readFileSync('updates.json'));
    //updateTrustlist();
 })
