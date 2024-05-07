import boto3
import jwt
import json

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('ifawf-about')

secret_client = boto3.client('secretsmanager')



def validate_auth(event):
    try:
        token = event['Authorization'].split(' ')
        if type(event['Authorization']) is not str or len(token) != 2 or token[0].lower() != 'bearer' or len(token[1]) == 0:
            return False
            
        secret_response = secret_client.get_secret_value(
            SecretId="ifawf-jwt-secret"
        )
        secret_dict = secret_response
        stored_secret = json.loads(secret_dict["SecretString"])['secret']
        decoded_secret = jwt.decode(token[1], stored_secret, algorithms=["HS256"])
        return True
    except Exception as e:
        print(str(e))
        return False
        

def validate_body(event):
    expected_keys = ['about']
    for key in event['body']:
        if key not in expected_keys or type(event['body'][key]) is not str:
            return False
    
    return True
    


def update_about(event):
    if validate_auth(event) == False or validate_body(event) == False:
        return {
            "status":401,
            "data":"Invalid request"
        }
    update = table.put_item(
        Item={
            'about':event['body']['about'],
            'main':'main'
        }
    )
    return {
        "status": 200,
        "data":event['body']['about']
    }


def get_about():
    body = table.get_item(
        Key={"main":"main"}
    )
    return {
        "status":200,
        "data":body['Item']['about']
    }


def lambda_handler(event, context):
    try:
        body = event
        if event['http_method'] == 'PUT':
            return update_about(event) 
        elif event['http_method'] == 'GET':
            return get_about()
        else:
            raise Exception("Internal Server Error")
    except Exception as e:
        return {
            "status":500,
            "data": str(e)
        }