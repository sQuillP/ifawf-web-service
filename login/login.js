// import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import {SecretsManagerClient, GetSecretValueCommand} from '@aws-sdk/client-secrets-manager';
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,

  GetCommand,
} from "@aws-sdk/lib-dynamodb";


/**
 * Description: Handle login logic for the admin portal. Use JWT for handing out tokens
 * and bcrypt for hashing & comparing passwords in DynamoDB
 */


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


async function fetchAdminUser(username) {
    const client = new DynamoDBClient({});
    const dynamo = DynamoDBDocumentClient.from(client);
    const adminTable = "ifawf-admin";

    const dbResponse = await dynamo.send(
        new GetCommand({
            TableName: adminTable,
            Key: {
                username
            }
        })
    );

    return dbResponse;
}


function validateRequest(event) {
    const expectedKeys = ["username","password"];
    for(const key of expectedKeys) {
        if(!event[key] || typeof(event[key]) !== 'string') {
            return false;
        }
    }
    return true;
}


async function getToken(payload) {
    const { secret } = JSON.parse(await getSecret());
    delete payload.password;
    const token = jwt.sign(payload, secret);
    return token;
}

export const handler = async (event, context)=> {
    try {
        // Validate the request
        if(validateRequest(event) == false) {
            return {
                status: 401,
                data:"Invalid body"
            }
        }
        //password is password123 by the way.
        const fetchedAdminUser = await fetchAdminUser(event.username);
        const validPassword = await bcrypt.compare(event.password,fetchedAdminUser.Item.password);
        if(validPassword == false) {
            return {
                status: 401,
                data:"Invalid Username or password"
            }
        }
        //Get the auth token finally
        const token = await getToken(event);
        return {
            status:200,
            data: token
        };
    } catch(error) {
        console.log("ERROR IN THE LOGIN HANDLER!",error, error.message);
        return {
            status: 500,
            data: "Internal server error."
        }
    }
}