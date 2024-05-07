import json
import boto3
import jwt
from datetime import datetime
from zoneinfo import ZoneInfo


ses = boto3.client('ses')
dynamodb = boto3.resource('dynamodb')
secret_client = boto3.client('secretsmanager')
"""
    NOTE: We are only handling custom made messages for emails.
    This does not include any events i.e, creating a new gathering. 
    That is going to be handled in another function.
"""

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
        },
        "body": json.dumps(body)
    }
    return resp
    
BAD_REQUEST = send_response(status=400, body={"data":"Invalid request body"})
NOT_AUTH = send_response(status=401, body={"data":"Not authorized"})

# SES config
SOURCE_EMAIL="indyfaithandworkforum@gmail.com"
MESSAGE_TEMPLATE="Email_all_subscribers"
NOTIFY_TEMPLATE="notify_new_event"


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


def validate_body(expected_keys, event):
    if len(event.keys()) != len(expected_keys):
        return False
    for key in event:
        if key not in expected_keys or type(event[key]) is not str:
            return False
    return True
    
    
# We want emails to be sent out when a new event gets scheduled
# We also want emails to be sent out when admin wants to let subscribers/site subscribers know any updates/news.


def send_ses_message_email(mail_list, email_message):
    """
        Description: Calls boto3 ses api for sending emails to many users.
    """
    ses.send_templated_email(
        Source=SOURCE_EMAIL,
        Destination={
            "ToAddresses":[SOURCE_EMAIL]
        },
        ReplyToAddresses=[SOURCE_EMAIL],
        Template=MESSAGE_TEMPLATE,
        TemplateData=json.dumps({"email_message":email_message})
    )


def send_ses_event_email(gathering, mail_list):
    """
        Description: Send an ses email to all users who are currently subscribed to the site.
        This is only for when NEW EVENTS are created, we want to notify all subscribed users of the newly created event.
    """
    # NOTE: Please format the date accordingly
    template_data={
        "start_date":"Friday, May 14", 
        "location":"117 West Windsor Ave, Lombard IL", 
        "start_time":"7pm",
        "extra_details":"Food and drinks will be provided."
    }
    ses.send_templated_email(
        Source=SOURCE_EMAIL,
        Destination={
            "ToAddresses":[SOURCE_EMAIL]
        },
        ReplyToAddresses=[SOURCE_EMAIL],
        Template=NOTIFY_TEMPLATE,
        TemplateData=json.dumps(template_data)
    )


def event_notify():
    gathering_response = dynamodb.Table('ifawf-gathering').query(**global_gathering_query)
    gathering = gathering_response['Items'][0]
    site_subscribers_response = dynamodb.Table('ifawf-subscribers').scan(
        Limit=100
    )
    email_list = []
    for user in site_subscribers_response['Items']:
        email_list.append(user['email'])
    
    send_ses_event_email(gathering=gathering, mail_list=email_list)

    while "LastEvaluatedKey" in site_subscribers_response:
        email_list = []
        last_key = site_subscribers_response['LastEvaluatedKey']
        site_subscribers_response = dynamodb.Table('ifawf-subscribers').scan(
            Limit=100,
            ExclusiveStartKey=last_key
        )
        for user in site_subscribers_response['Items']:
            email_list.append(user['email'])
        if len(email_list) > 0:
            send_ses_event_email(gathering=gathering,mail_list=email_list)
    return send_response(status=200, body={"data":"successfully sent email?"})


    



def email_subscribers(event,table):
    """
        Description: Grab all users from the desired table 'ifawf-event-subscribers' | 'ifawf-subscribers'
        and send them the message provided in the body.
    """
    subscribers_response = dynamodb.Table(table).scan(
        Limit=100
    )
    email_list = []
    for user in subscribers_response['Items']:
        email_list.append(user['email'])
    
    print(email_list)
    send_ses_message_email(mail_list=email_list, email_message="From aws lambda")
    # Paginate the body if there are still more emails to be sent out.
    while 'LastEvaluatedKey' in subscribers_response:
        email_list = []
        last_key = subscribers_response['LastEvaluatedKey']
        subscribers_response = dynamodb.Table(table).scan(
            Limit=100,
            ExclusiveStartKey=last_key
        )
        for user in subscribers_response['Items']:
            email_list.append(user['email'])
        print(email_list)
        if len(email_list) > 0:
            send_ses_message_email(mail_list=email_list, email_message="From aws lambda")
    
    return send_response(status=200, body={"data":"Successfully notified users!"})


def lambda_handler(event, context):
    """
        
    """
    if validate_auth(event['headers']) == False:
        return NOT_AUTH
    print("EVENT", event)
    if 'type' not in event['queryStringParameters']:
        return BAD_REQUEST
    q = event['queryStringParameters']
    if q['type'] == 'all':
        print('emailing ALL subscribers (ifawf-subscribers)')
        return email_subscribers(event, 'ifawf-subscribers')
    elif q['type'] == 'event':
        print('emailing EVENT subscribers (ifawf-event-subscribers)')
        return email_subscribers(event, 'ifawf-event-subscribers')
    elif q['type'] == 'event-notify':
        return event_notify()
    else:
        return BAD_REQUEST