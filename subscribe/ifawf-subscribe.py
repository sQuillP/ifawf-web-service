import json
import boto3
import jwt
import traceback
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource('dynamodb')
client = boto3.client('dynamodb',region_name='us-east-2')

secret_client = boto3.client('secretsmanager')


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


def already_exists(email, table):
    """
        Description: Return true if email already exists in the database.
        We have to manually check this since email is not standalone partition key.
    """

    fetch_email_user_query = {
        "TableName": "ifawf-subscribers",
        "KeyConditionExpression":"#email = :email",
        "ScanIndexForward":False,
        "ExpressionAttributeValues": {
        ":email":email,  
        },
        "ExpressionAttributeNames": {
            "#email":"email"
        },
        "Limit": 1
    }

    # Check if there is a user with same email in site subscribers table.
    if table =='ifawf-subscribers':
        site_response = dynamodb.Table(table).query(**fetch_email_user_query)

        # True if there exists a user in the site subscribers table.
        return len(site_response['Items']) != 0

    # Check if there is a user with the same email in the event subscribers table.
    elif table == 'ifawf-event-subscribers':
        event_response = dynamodb.Table('ifawf-gathering').query(**global_gathering_query)

        # This case would probably never be true
        if len(event_response['Items']) == 0:
            return False
        
        event = event_response['Items'][0]
        event_sub_response = dynamodb.Table(table).get_item(
            Key={'eventid':event['created'], 'email':email}
        )

        # True if user exists in event subscriber table
        return 'Item' in event_sub_response
    
    else:
        raise Exception("Invalid table name")

def create_site_subscriber(event):
    """
        Description: Users will be subscribed to the entire site. They can receive notifications through this 
        channel as well depending if the admin sends emails to them.
    """
    body = json.loads(event['body'])
    if validate_body(expected_keys=['email','firstName','lastName', 'dateJoined'], event=body) == False:
        return BAD_REQUEST
    
    if already_exists(body['email'], 'ifawf-subscribers') == True:
        return send_response(status=200, body={"data":"User site subscriber already exists!"})
    
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
    
    event_response = dynamodb.Table('ifawf-gathering').query(**global_gathering_query)

    # Check for existence of an event.
    if len(event_response['Items']) == 0 or body['eventid'] != event_response['Items'][0]['created']:
        return send_response(status=204, body={"data":"Event does not even exist"})
    
    # Check for user already existing with the same email.
    if already_exists(body['email'], 'ifawf-event-subscribers') == True:
        return send_response(status=200, body={"data":"User event subscriber already exists!"})
    
    # Add user to the evnet subscription
    dynamodb.Table("ifawf-event-subscribers").put_item(Item=body)
    return send_response(status=200, body={"data":"Successfully subscribed to event"})
    
    
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


def get_subscriber_email(dateJoined):
    """
        Description: Extract the subscribers email address from any 
        of the existing tables using gsi dateJoined.
        Returns:
            email:str|None - email of the user that is shared in both tables.
            None if there is no matching datejoined user.
            
    """
    dbTables = ['ifawf-event-subscribers','ifawf-subscribers']
    for table in dbTables:
        subscriberResponse = dynamodb.Table(table).query(
            IndexName='dateJoined-index',
            KeyConditionExpression=Key('dateJoined').eq(dateJoined)
        )
        if len(subscriberResponse['Items']) != 0:
            return subscriberResponse['Items'][0]['email']
    return None


def handle_delete(event):
    """
        Description: When endpoint gets hit, we will remove a site subscriber from 
        site and event notifications.
        * Get the users email
        * Query all channel tables using users email
        * Delete user in each table using email as a partition/sort key
    """
    body = json.loads(event['body'])

    # Make sure that dateJoined keyword is specified. This is used as gsi
    # lookup for deleting the user.
    if validate_body(expected_keys=['dateJoined'], event=body) == False:
        return BAD_REQUEST
    
    user_email = get_subscriber_email(body['dateJoined'])

    if user_email is None:
        return send_response(status=204, body={"data":"no such user exists"})
    
    fetch_email_user_query = {
        "TableName": "ifawf-subscribers",
        "KeyConditionExpression":"#email = :email",
        "ScanIndexForward":False,
        "ExpressionAttributeValues": {
        ":email":user_email,  
        },
        "ExpressionAttributeNames": {
            "#email":"email"
        },
        "Limit": 1
    }

    # We first fetch the site subscribers
    fetched_user = dynamodb.Table('ifawf-subscribers').query(**fetch_email_user_query)

    # Remove the site subscriber if possible
    if len(fetched_user['Items']) != 0:
        user = fetched_user['Items'][0]
        print(user)
        deleteResponse = dynamodb.Table('ifawf-subscribers').delete_item(
            Key={"email":user['email'], "dateJoined":user['dateJoined']}
        )
    
    # Fetch the global gathering query to extract part of the primary key
    fetched_event = dynamodb.Table('ifawf-event-subscribers').query(**global_gathering_query)

    # Remove event subscriber if possible
    if len(fetched_event['Items']) != 0:
        deleteResponse = dynamodb.Table('ifawf-event-subscribers').delete_item(
            Key={"email":user_email, "eventid":fetched_event['Items'][0]['created']}
        )

    return send_response(status=200, body={"data":"Successfully removed subscriber from all channels"})


def lambda_handler(event, context):
    q = event['queryStringParameters']
    try:
        if event['httpMethod'] == 'GET':
            return handle_get(q, event)
        elif event['httpMethod'] == 'POST':
            return handle_post(q, event)
        elif event['httpMethod'] == 'DELETE':
            return handle_delete(event=event)
        else:
            raise Exception("something wrong")
    except Exception as e:
        print("ERROR STRING",str(e))    
        traceback.print_exc()
        body = {
            "data": "Internal Server Error"
        }
        return send_response(status=500, body=body)