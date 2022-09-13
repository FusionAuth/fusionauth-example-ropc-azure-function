const graph = require("./graph");
require("isomorphic-fetch");
const querystring = require("querystring");
const jwt = require("jsonwebtoken");

module.exports = async function (context, req) {
  context.log("JavaScript HTTP trigger function processed a request.");
  const tenantName = process.env.TENANT_NAME;
  const tenantId = process.env.TENANT_ID;
  const appName = process.env.APP_NAME;

  const tokenUrl = `https://${tenantName}.b2clogin.com/${tenantId}/${appName}/oauth2/v2.0/token`;
  const tokenRequest = {
    username: req.body.loginId, // "user@example.com",
    password: req.body.password, //"verystrongpassword11!",
    grant_type: "password",
    scope: "openid 022c5902-d8ee-43b0-ac1f-c2719b799657",
    client_id: "022c5902-d8ee-43b0-ac1f-c2719b799657",
    response_type: "token",
  };

  let tokenResponse = await fetch(tokenUrl, {
    method: "POST",
    body: querystring.stringify(tokenRequest),
    headers: {
      "Content-type": "application/x-www-form-urlencoded",
    },
  });

  if (tokenResponse.ok) {
    let body = await tokenResponse.json();
    const decodedToken = jwt.decode(body.access_token);
    let user = await graph.getUser(decodedToken.oid);
    let fusionUser = transformToFusionUserObject(user); 
    context.res = {
      status: 200, 
      body: {user: fusionUser},
    };
  } else {
    // Something not great with username
    context.res = {
      status: 404,
      body: await tokenResponse.json(),
    };
  }

  context.log(JSON.stringify(context.res));
};

function transformToFusionUserObject(azureUser) {
  let localIdentity = azureUser.identities.find(i=>i.signInType==="emailAddress"); //{|i|i["signInType"]==="emailAddress"}
  let epochTime = new Date(azureUser.createdDateTime); 
  epochTime = epochTime.getTime()/1000;
  let fusionUser = {
    id: azureUser.id,
    active: azureUser.accountEnabled, 
    firstName: azureUser.givenName,
    fullName: azureUser.displayName,
    lastName: azureUser.surname,
    username: azureUser.userPrincipalName,
    email: localIdentity.issuerAssignedId,
    verified: true,
    insertInstant: epochTime,
    data :{
        azure:{
            identities: azureUser.identities
        }
    }
  }
  return fusionUser; 
}
