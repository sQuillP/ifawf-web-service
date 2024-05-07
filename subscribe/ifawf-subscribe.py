import json
import boto3
import jwt
import traceback
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource('dynamodb')
client = boto3.client('dynamodb',region_name='us-east-2')

secret_client = boto3.client('secretsmanager')


def send_response(status, body):
    resp = {
        "isBase64Encoded": False,
        "statusCode": status,
        "headers": {
            "Content-Type" : "application/json",
            "Access-Control-Allow-Origin" : "*",
            "Allow" : "GET, OPTIONS, POST",
            "Access-Control-Allow-Methods" : "GET, OPTIONS, POST",
            "Access-Control-Allow-Headers" : "*"
        },
        "body": json.dumps(body)
    }
    return resp
    
BAD_REQUEST = send_response(status=400, body={"data":"Invalid request body"})
NOT_AUTH = send_response(status=401, body={"data":"Not authorized"})



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
        # raises exception
        decoded_secret = jwt.decode(token[1], stored_secret, algorithms=["HS256"])
        return True
    except Exception as e:
        print(str(e))
        return False

# Just handle some pagination, not sure why I called it ins...
def ins(query, scan_query):
    if query['ExclusiveStartKey'] != '':
        st = query['ExclusiveStartKey']
        st = st.split(" ")
        if len(st) != 2 or "@" not in st[1]:
            return False
        start_key={
            "eventid":st[0],
            "email":st[1]
        }
        scan_query['ExclusiveStartKey'] = start_key
    return True



def validate_body(expected_keys, event):
    if len(event.keys()) != len(expected_keys):
        return False
    for key in event:
        if key not in expected_keys or type(event[key]) is not str:
            return False
    return True
    

def get_all_subscribers(query):
    if validate_body(expected_keys=['type', 'limit', 'ExclusiveStartKey'], event=query) == False:
        return BAD_REQUEST
    scan_query = {
        "Limit": int(query['limit']),

    }
    # handle pagination eventually
    count_response = dynamodb.Table('ifawf-subscribers').scan(Select="COUNT")
    item_count = count_response["Count"]
    # paginate if startkey is provided
    if query['ExclusiveStartKey'] != '':
        scan_query['ExclusiveStartKey'] = {"email":query['ExclusiveStartKey']}
    subscribers_response = dynamodb.Table('ifawf-subscribers').scan(**scan_query)
    LastEvaluatedKey = ''
    # Make sure that users get the last evaluated paginated key
    if 'LastEvaluatedKey' in subscribers_response:
        LastEvaluatedKey = subscribers_response['LastEvaluatedKey']
    response_data =  {
        'data': subscribers_response['Items'],
        'count':item_count,
        "ExclusiveStartKey":LastEvaluatedKey
    }
    return send_response(status=200,body=response_data)


def get_event_subscribers(query):
    if validate_body(expected_keys=['type','limit', 'ExclusiveStartKey', 'eventid'], event=query) == False:
        print('invalid body',query)
        return BAD_REQUEST
    scan_query= {
        "Limit":int(query['limit']),
        "KeyConditionExpression":Key('eventid').eq(query['eventid']),
    }
    # Handle pagination
    if ins(query=query, scan_query=scan_query) == False:
        return BAD_REQUEST
    count_response = dynamodb.Table('ifawf-event-subscribers').query(Select="COUNT", KeyConditionExpression=Key('eventid').eq(query['eventid']))
    item_count = count_response['Count']
    subscribers_response = dynamodb.Table('ifawf-event-subscribers').query(**scan_query)
    LastEvaluatedKey = ''
    if 'LastEvaluatedKey' in subscribers_response:
        LastEvaluatedKey = subscribers_response['LastEvaluatedKey']
    response_data = {
        "data": subscribers_response['Items'],
        'count':item_count,
        "ExclusiveStartKey": LastEvaluatedKey
    }
    return send_response(status=200, body=response_data)
    

def create_site_subscriber(event):
    """
        Description: Users will be subscribed to the entire site. They can receive notifications through this 
        channel as well depending if the admin sends emails to them.
    """
    body = json.loads(event['body'])
    if validate_body(expected_keys=['email','firstName','lastName', 'dateJoined'], event=body) == False:
        return BAD_REQUEST
    dynamodb.Table('ifawf-subscribers').put_item(
        Item=body
    )
    return send_response(status=200, body={"data":"Successfully subscribed"})


def create_event_subscriber(event):
    """
        Description: User will subscribe to a certain even. I.E, they will get to hear updates about the current 
        ongoing event.
    """
    body = json.loads(event['body'])
    
    if validate_body(expected_keys=['eventid','email','firstName',"lastName", 'dateJoined'],event=body) == False:
        return BAD_REQUEST
    dynamodb.Table("ifawf-event-subscribers").put_item(Item=body)
    return send_response(status=200, body={"data":"Successfully subscribed to event"})


def delete_site_subscriber(event):
    """
        Description: Remove user from the email list
    """
    body = json.loads(event['body'])
    if validate_body(expected_keys=["email", ], event=body) == False:
        return BAD_REQUEST
    
    dynamodb.Table("ifawf-subscribers").delete_item(
        Key=body
    )
    
    return send_response(status=200, body={"data":"Successfully removed item from db."})


def delete_event_subscriber(event):
    """
        Description: Remove user from the email list
        NOTE: this is definitely identical to the other delete function but this second
        one is here anyway. Let's just keep this plain
    """
    body = json.loads(event['body'])
    if validate_body(expected_keys=["email",'eventid'], event=body) == False:
        return BAD_REQUEST
    
    dynamodb.Table("ifawf-event-subscribers").delete_item(
        Key=body
    )
    
    return send_response(status=200, body={"data":"Successfully removed item from db."})
    
    
def handle_get(query, event):
    """
        Description: Handle get requests for event and site subscribers.
    """
    if validate_auth(event['headers']) == False:
        return NOT_AUTH
    if query is None or 'type' not in query:
        return BAD_REQUEST
    elif query['type'] == 'all':
        return get_all_subscribers(query)
    elif query['type'] == 'event':
        return get_event_subscribers(query)
    else:
        return BAD_REQUEST

def handle_post(query, event):
    if query is None or 'type' not in query:
        return BAD_REQUEST
    elif query['type'] == 'all':
        return create_site_subscriber(event)
    elif query['type'] == 'event':
        return create_event_subscriber(event)
    else:
        return BAD_REQUEST
    


def handle_delete(query, event):
    if query is None or 'type' not in query:
        return BAD_REQUEST
    # Possibly check if user has a permanent auth token.
    if query['type'] == 'all':
        return delete_site_subscriber(event)
    elif query['type'] == "event":
        return delete_event_subscriber(event)
    else:
        return BAD_REQUEST

def lambda_handler(event, context):
    q = event['queryStringParameters']
    try:
        if event['httpMethod'] == 'GET':
            return handle_get(q, event)
        elif event['httpMethod'] == 'POST':
            return handle_post(q, event)
        elif event['httpMethod'] == 'DELETE':
            return handle_delete(q, event)
        else:
            raise Exception("something wrong")
    except Exception as e:
        print("ERROR STRING",str(e))    
        traceback.print_exc()
        body = {
            "data": "Internal Server Error"
        }
        return send_response(status=500, body=body)