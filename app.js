const express = require('express');
const dotenv = require('dotenv');
const request = require('request');
const https = require('https');
const fs = require('fs');
const jose = require('node-jose');
const Axios = require('axios');

const port = process.env.port || 5000;

const key = fs.readFileSync('./key_f055f855-0b5f-4fc9-942f-c329782b5872.pem');
 const cert = fs.readFileSync('./cert.pem')//const cert = fs.readFileSync('./DigiCertGlobalRootCA.crt')

// const ca = fs.readFileSync('./VDPCA-SBX.pem')
// console.log(key,cert)
dotenv.config();

const createEncryptedPayload =  async (body) => {
  //var text = fs.readFileSync(config.mlePublicKeyPath);
  //var string = text.toString('utf-8');
  
  var kid = process.env.KID
  let dataEnc;
  return jose.JWK.asKey(fs.readFileSync(process.env.SERVER_KEY), 'PEM', {"kty": "RSA", "alg": "RSA-OAEP-256", "kid" : kid,enc: "A128GCM", key_opts: ["wrapKey","enc"]})
   .then(function(result) {
       return encryptionResult = jose.JWE.createEncrypt({format : 'compact', contentAlg: 'A128GCM', fields: {iat: Date.now()}},result).update(JSON.stringify(body)).final()
            .then(function(data) {
				
				dataEnc=data.toString();

				return dataEnc;
				  
                });
            }).catch(function(reason) {
                console.log('Encryption failed due to ');
                console.log(reason);
            });
}

const decrypt = (data) => {

 var dataDcrypt = data;
  return jose.JWK.asKey(fs.readFileSync(process.env.MLE_KEY), 'PEM').then(function(result){
                    return  jose.JWE.createDecrypt(result).decrypt(dataDcrypt, {contentAlg: 'A128GCM', alg: 'RSA-OAEP-256'})
                       .then(function(decryptedResult){  
							var decResult = String(decryptedResult.plaintext);
							//console.log(decResult)		
							return 	decResult;				
							//  response.setHeader('Content-Type', 'application/json');
							// response.send(String(decryptedResult.plaintext));
                        });
                    }).catch(function(reason) {
                console.log('Descryption failed due to ');
                console.log(reason);
            });

}

const checkTokenStatus = async (req,res) => {
	try
	{
		if(!req.body.pan)
			res.status(400).json({status : 'fail',message : 'provide pan number'});
	
		const pan = req.body.pan;

		const r = request.defaults();

		const time = new Date();

		const date = `${time.getFullYear()}-0${time.getMonth()}-0${time.getDate()} ${time.getHours()}:${time.getMinutes()}:${time.getSeconds()}:${time.getMilliseconds()}`;
		console.log(date);
		const data = {
		  "requestHeader": {
		    "requestMessageId": "6da6b8b024532a2e0eacb1af58581",
		    "messageDateTime": `${date}`
		  },
		  "requestData": {
		    "pANs": [
		      req.body.pan
		    ],
		    "group": "STANDARD"
		  }
		}

		const encpData = await createEncryptedPayload(data);
		encData = {
		    	"encData" : encpData
		    }

		// console.log(encpData)
		 const url  = "https://sandbox.api.visa.com/cofds-web/v1/datainfo";

		const requ = {
			url  : "https://sandbox.api.visa.com/cofds-web/v1/datainfo",
			method : 'POST',
		    headers: {
		      'Content-Type' : 'application/json',
		      'Accept' : 'application/json',
		      'keyId' : '43545213-06fa-46e6-9952-b2475a7642f0',
		      'Authorization' : 'Basic MEJHN1NDNlRDMlgxN0lGNVhTSlcyMWphSlJvUG1lNkJ2ZTNxTXJ5MnF5cUlaRUFqQTp3T3hRNlMyaU84c2pYOWNEWEQ=' 
		    },
		   data : encData,
		    httpsAgent : new https.Agent({
		    	cert :cert,
		    	key : key
		    })
  		}

  		console.log(Date(Date.now()));

  		return await Axios(requ).then(async data => {
  			// console.log(data.data)
  			 const r = await decrypt(data.data.encData)
  			// console.log(data)
  			res.status(data.status).json(JSON.parse(r))
  		}).catch(async err => {
  			// console.log(err)
  			const data = await decrypt(err.response.data.encData)
  			// console.log(data)
  			res.status(err.response.status).json(JSON.parse(data))
  			// console.log(err.response.data)
  			return;
  		});


  		// console.log(resp.data);
  		res.status(200).json({
  			data
  		});

	} catch(err) {
		console.log(err);
		res.status(500).json({
			status : 'internal server error'
		})
	}
}

const app = express();
app.use(express.json());

app.post('/',checkTokenStatus)/*(req,res) => {
	res.json({
		data : req.headers
	})
})
*/
app.listen(port,() => console.log(`App Running in port : ${port}`));