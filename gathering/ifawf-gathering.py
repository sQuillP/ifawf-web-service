import json
import boto3
import jwt

dynamodb = boto3.resource('dynamodb')

table=dynamodb.Table('ifawf-gathering')
secret_client = boto3.client('secretsmanager')


#Query for getting the latest gathering.
global_gathering_query = {
    "TableName": "ifawf-gathering",
    "KeyConditionExpression":"#main = :main",
    "ScanIndexForward":False,
    "ExpressionAttributeValues": {
      ":main":"main"  
    },
    "ExpressionAttributeNames": {
        "#main":"main"
    },
    "Limit": 1
}

BAD_REQUEST = {"status":400, "data":"Invalid request body"}
UNAUTHORIZED = {"status":401, "data":"Not authorized"}

def validate_auth(event):
    """
        Check if auth header is present, adn then validate the token.
        Returns:
            bool - True if auth header is valid, False otherwise.
    """
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


def validate_body(expected_keys, event):
    if len(event['body'].keys()) != len(expected_keys):
        return False
    for key in event['body']:
        if key not in expected_keys or type(event['body'][key]) is not str:
            return False
    return True


def get_event():
    
    current_event = table.query(**global_gathering_query)
    return {
        "status":200,
        "data":current_event['Items']
    }



def update_event(event, method):
    status=200
    if validate_auth(event) == False:
        return UNAUTHORIZED
    elif validate_body(expected_keys=['main','created','date','location','timeEnd'],event=event) == False:
        return BAD_REQUEST
    else:
        table.put_item(
            TableName='ifawf-gathering',
            Item=event['body']
        )
        if method =='POST':
            status = 201
        updated_table = table.query(**global_gathering_query)
        return {
            "status":status,
            "data": updated_table['Items']
        }


def delete_event(event):
    if validate_auth(event) == False:
        return UNAUTHORIZED
    elif validate_body(expected_keys=['main','created'], event=event) == False:
        return BAD_REQUEST
    else:
        table.delete_item(
            Key=event['body']
        )
        updated_items = table.query(**global_gathering_query)
        return {
            "status":200,
            "data": updated_items['Items']
        }




def lambda_handler(event, context):
    try:
        if event['http_method'] == 'GET':
            return get_event()
        elif event['http_method'] == 'POST' or event['http_method'] =='PUT':
            return update_event(event,event['http_method'])
        elif event['http_method'] == 'DELETE':
            return delete_event(event)
        else:
            raise Exception("Invalid http method.")
    except Exception as e:
        print(str(e))
        return {
            'statusCode': 500,
            'data':'Internal server error'
        }
