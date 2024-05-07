import boto3
import jwt
import json



dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('ifawf-links')
secret_client = boto3.client('secretsmanager')


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
        

def validate_request_body(event):
    expected_keys = ['title', 'link']
    if len(event['body'].keys()) != 2:
        return False
    for key in event['body']:
        if key not in expected_keys or type(event['body'][key]) is not str:
            return False
    
    return True

"""
    link: {
        title: string,
        link: string
    }

"""

def get_links():
    # No auth required for getting links (read only)
    link_results = table.scan(
        TableName="ifawf-links",
        Limit=100
    )
    print("LINK RESULTS", link_results)
    return {
        "status":200,
        "data":link_results["Items"]
    }



def create_link(event):
    # Validate request body
    print("VALID REQ BODY", validate_request_body(event))
    if validate_request_body(event) == False:
        return {
            "status":400,
            "data":"Invalid request body"
        }
    # Ensure that admin is logged in
    elif validate_auth(event) == False:
        return {
            "status":401,
            "data":"Not authorized"
        }
    else:
        # Update the links
        table.put_item(
            TableName="ifawf-links",
            Item=event['body']
        )
        # Make sure you send back the updated links
        total_links = table.scan(
            TableName="ifawf-links",
            Limit=100
        )["Items"]
        # Send the created status with updated link list.
        return {
            "status":201,
            "data": total_links
        }


def lambda_handler(event, context):
    try:
        print(event)
        if event['http_method'] == 'GET':
            return get_links()
        elif event['http_method'] == 'POST':
            return create_link(event)
        elif event['http_method'] == 'PUT':
            return create_link(event)
        else:
            raise Exception("Invalid HTTP method")
    except Exception as e:
        print(str(e))
        return {
            "status":500,
            "data":"Internal server error"
        }