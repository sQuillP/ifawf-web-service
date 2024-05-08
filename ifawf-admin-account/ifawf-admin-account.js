// import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import {SecretsManagerClient, GetSecretValueCommand} from '@aws-sdk/client-secrets-manager';
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {DynamoDB} from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  DynamoDBDocument,
  PutCommand,
  DeleteCommand,
  GetCommand,
} from "@aws-sdk/lib-dynamodb";


/**
 * Description: Handle account management for the admin user .
 */

const BAD_REQUEST = sendResponse(400,{"data":"Invalid request body"});
const NOT_AUTH = sendResponse(401, {"data":"Not authorized"});


function sendResponse(status, body) {
    const resp = {
        "isBase64Encoded": false,
        "statusCode": status,
        "headers": {
            "Content-Type" : "application/json",
            "Access-Control-Allow-Origin" : "*",
            "Allow" : "GET, OPTIONS, POST",
            "Access-Control-Allow-Methods" : "GET, OPTIONS, POST",
            "Access-Control-Allow-Headers" : "*"
        },
        "body": JSON.stringify(body)
    }
    return resp;
}


async function validateToken(header) {
    try {
        const { secret } = JSON.parse(await getSecret());
        console.log(header);
        console.log("HEADER AUTH::: ", header.Authorization);
        const splitToken = header.Authorization.split(' ');
        if(splitToken.length !== 2 || splitToken[0].toLowerCase() !== 'bearer') {
            console.log('should return false')
            return false;
        }
        console.log("TOKEN ITSELF::: ",splitToken[1]);
        const validToken = jwt.verify(splitToken[1],secret);
        return true;
    } catch(error) {
        console.log(error, error.message)
        return false;
    }
}



async function getSecret() {
    try {
        const client = new SecretsManagerClient({
            region: "us-east-2"
        });
        const input = {
            SecretId:'ifawf-jwt-secret',
        };
        const command = new GetSecretValueCommand(input);
        const response = await client.send(command);
        return response.SecretString;
    } catch(error) {
        console.log("Error in getSecret()", error.message);
    }
}


/**
 * @description Return current admin root user.
 * @returns object of the current root admin user.
 */
async function fetchAdminUser(username) {
    const client = new DynamoDB({});
    const ddbDocClient = DynamoDBDocument.from(client);
    const scanResult = await ddbDocClient.scan({TableName:'ifawf-admin'});
    const user = scanResult.Items[0];
    return user;
}


function validateRequest(expectedKeys, event) {
    for(const key of expectedKeys) {
        if(!event[key] || typeof(event[key]) !== 'string') {
            return false;
        }
    }
    return true;
}


/**
 * @description When changing username, we create another db user with the desired username, 
 * and existing password. Then we delete the current existing user with the old username. this will in effect just 
 * update the username.
 * @returns 
 */
async function changeUsername(event) {
    try {
        const body = JSON.parse(event.body);
        if(validateRequest(['username'], body) === false) {
            return BAD_REQUEST;
        }
        if(body.username.trim().length === 0) {
            return BAD_REQUEST;
        }
        const client = new DynamoDBClient({});
        const dynamo = DynamoDBDocumentClient.from(client);

        //Fetch the current user
        console.log('before fetchadminuser');
        const currentAdminUser = await fetchAdminUser(body.username);
        console.log('event', event)
        //This will create another db user. We only want one though, so we follow through with a delete.
        const putResponse = await dynamo.send(
            new PutCommand({
                TableName:'ifawf-admin',
                Item: {
                    username:body.username,
                    password: currentAdminUser.password,
                }
            })
        );
        
        console.log('after putResponse');
        if(currentAdminUser.username !== body.username) {
            //Delete current instance since username is the primary key of the db item.
            const deleteResponse = await dynamo.send(
                new DeleteCommand({
                    Key: {username:currentAdminUser.username},
                    TableName:'ifawf-admin'
                })
            );
        }
        console.log('after deleteResponse');
        return sendResponse(200,{"data":"successfully updated user with username '"+body.username+"'"});
    } catch(error) {
        console.log('error in changeusername', error);
        return BAD_REQUEST
    }
}

/**
 * @description Change a users password when executed.
 */
async function changePassword(event) {
    try {
        const body = JSON.parse(event.body);
        if(validateRequest(['oldPassword', 'newPassword'], body) === false) {
            return BAD_REQUEST;
        }
        console.log('changing password');
        console.log('why is this not logging!');
        // Grab the current admin user
        const currentUser = await fetchAdminUser();
        // Make sure that passwords match for doing this
        const validPassword = await bcrypt.compare(body.oldPassword, currentUser.password);
        console.log('validated password', validPassword)
        if(validPassword === false) {
            return BAD_REQUEST;
        }
        //Ensure that the password is hashed.
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(body.newPassword,salt);
        
        const client = new DynamoDBClient({});
        const dynamo = DynamoDBDocumentClient.from(client);
        const putResponse = await dynamo.send(
            new PutCommand({
                TableName:'ifawf-admin',
                Item:{
                    username:currentUser.username,
                    password:hash
                }
            })
        );
        console.log('shoudl update the password')
        return sendResponse(200, {'data':'Successfully updated password'})
    } catch(error) {
        console.log(error);
        return BAD_REQUEST;
    }
}



/**
 * @description Ensure that user is authenticated with the correct query param headers.
 * @returns 
 */
export const handler = async (event, context)=> {
   try {
    const q = event.queryStringParameters;
    if((await validateToken(event.headers)) === false){
        console.log("RETURNING NOT AUTH");
        return NOT_AUTH;
   }else if(validateRequest(['event'],q) === false) {
        return BAD_REQUEST;
    }
    //now perform any action you need
    if(q.event === 'username') {
        return changeUsername(event);
    } else if(q.event === 'password') {
        return changePassword(event);
    } else {
        return BAD_REQUEST;
    }
   } catch(error) {
    return sendResponse(500,"Internal Server Error");
   }
}