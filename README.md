# Project
Made during the security lecture 2021, a little rest api validating covid certificates with the current (Oct 2021) rules in Switzerland.

## Routes
1. `/verify`, needs a json body with the field `cert`, which is the string from the certificate `HC1:...` or `LT1:..`
  can contain `signcert`, which is the signing certificate (for the demo qrcodes)
  returns 
    - {valid: false, reason: \<MESSAGE>}
    - {valid: true|false, type: 'V'|'R'|'T', iss: \<Country-Code>, iss_at: \<TIMESTAMP>, data: \<DATA ACCORDING EU SPECIFICATION>}
1. `/lastUpdate`
  returns two timestamps when the active keys and their codes were last updated

## Live server
May be slow to startup: https://covid-qr-backend.herokuapp.com/

## Run it local
1. Clone the repo and change into its directory
1. `npm install`
1. `node index.js`

Make sure to change the verify url in the frontend (qr-impl.js:6)
