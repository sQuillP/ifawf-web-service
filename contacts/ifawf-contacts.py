import json
import jwt
import boto3


dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('ifawf-contacts')
secret_client = boto3.client('secretsmanager')



BAD_REQUEST = {"status":400, "data":"Invalid request body"}
NOT_AUTH = {"status":401, "data":"Not authorized"}


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


def add_contact(event, method):
    status = 201
    expected_keys = ['firstName','lastName','email','phone', 'image']
    print("PUT/POST EVENT", event, method)
    if validate_body(expected_keys=expected_keys, event=event) == False:
        return BAD_REQUEST
    elif validate_auth(event) == False:
        return NOT_AUTH
    else:
        # Add/Update item in dynamo
        table.put_item(
            TableName="ifawf-contacts",
            Item=event['body']
        )
        # Return list of all contacts
        total_contacts = table.scan(
            TableName='ifawf-contacts',
            Limit=100
        )
        # Change status to OK if it's just a put
        if method == 'PUT':
            status=200
        return {
            "status":status,
            "data": total_contacts['Items']
        }


def get_contacts(event):
    all_contacts = table.scan(
        TableName="ifawf-contacts",
        Limit=100
    )
    return {
        "status":200,
        "data": all_contacts["Items"]
    }


def delete_contact(event):
    expected_keys = ['email']
    if validate_body(expected_keys=expected_keys, event=event) == False:
        return BAD_REQUEST
    elif validate_auth(event) == False:
        return NOT_AUTH
    else:
        table.delete_item(
            Key=event['body']
        )
        updated_contacts = table.scan(
            TableName="ifawf-contacts",
            Limit=100
        )
        return {
            "status":200,
            "data": updated_contacts["Items"]
        }

def lambda_handler(event, context):
    try:
        if event['http_method'] == 'GET':
            return get_contacts(event)
        elif event['http_method'] == 'PUT' or event['http_method'] == 'POST':
            return add_contact(event,event['http_method'])
        elif event['http_method'] == 'DELETE':
            return delete_contact(event)
        else:
            raise Exception("Invalid HTTP method")
    except Exception as e:
        print(str(e))
        return {
            "status":500,
            "data":"Internal Server Error"
        }
