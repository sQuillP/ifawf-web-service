import json
import boto3
import jwt
from datetime import datetime, date, timedelta
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import *


ses = boto3.client('ses')
dynamodb = boto3.resource('dynamodb')
secret_client = boto3.client('secretsmanager')
"""
    NOTE: We are only handling custom made messages for emails.
    This does not include any events i.e, creating a new gathering. 
    That is going to be handled in another function.

    NOTE: There is a known bug in this code that has will not have the correct time on the start and end of daylight savings.
    this should be eventually fixed.

    TODO: Add user dateJoined id's to unsubscribe to email listing. Please have this done by this week.
    Delete operation is already there,
    create operation is already there.

    Please work on this as soon as possible.
"""




# print(fmt.day, fmt.month, fmt.hour, fmt.weekday())
# print("Try programiz.pro")

months = [
        'January',
        'February',
        'March',
        'April',
        'May',
        'June',
        'July',
        'August',
        'September',
        'October',
        'November',
        'December'
    ]
    
days = ['Monday','Tuesday',"Wednesday",'Thursday','Friday','Saturday','Sunday']
    
    
def get_EST_daylight_offset(fmt):
    """
        Description: Any Months before march will have an offset of -5 hours from 
        UTC. Any time past the second sunday of March will have an offset of -4 hours
        for EST time.
    """
    first_march = date(year=fmt.year, month=3,day=1)
    first_november = date(year=fmt.year, month=11, day=1)

    print(fmt.day, 6-first_march.weekday()+7+1)

    print( (6-first_november.weekday()+1))
    # lt 3 or greater than 11
    if fmt.month < 3 or fmt.month > 11:
        return 5
    # Before the second sunday of march (daylight savings begins)
    elif months[fmt.month-1] == 'March' and fmt.day < ( 6 - first_march.weekday() + 7 + 1):
        return 5
    #after the first sunday of november (daylight savings ends)
    elif months[fmt.month-1] == 'November' and fmt.day >= (6-first_november.weekday()+1):
        return 5
    # between any of those days
    else:
        return 4


def get_formatted_hour(iso):
    """
        Description: Get the formatted string/object based on iso date.
    """
    fmt = datetime.fromisoformat(iso)
    hours = fmt.hour
    daytime = 'am'
    

    hours -= get_EST_daylight_offset(fmt)

    
    if hours > 12:
        hours -=12
        daytime='pm'
    
    if hours <= 0:
        hours += 12
        daytime='pm'
        
    if hours == 12:
        daytime='am'
    
    return f"{hours}{daytime}"


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

# SES config (deprecated)
SOURCE_EMAIL="indyfaithandworkforum@gmail.com"
MESSAGE_TEMPLATE="Email_all_subscribers"
NOTIFY_TEMPLATE="notify_new_event"
UNSUBSCRIBE_TEMPLATE='ifawf_unsubscribe'
BASE_URL='http://indyfaithandworkforum.org'

UNSUBSCRIBE_URL='https://indyfaithandworkforum.org/unsubscribe'

#sendgrid configuration
SENDGRID_API_KEY = 'You thought lol'
SENDGRID_EVENT_TEMPLATE_ID = 'd-89e760648294447b9aac0fc1142206a5'
SENDGRID_NOTIFICATION_TEMPLATE_ID = "d-aacda58488294a4a8230d404d809cbfe"
SENDGRID_UNSUBSCRIBE_TEMPLATE_ID = 'd-cc7711ec75a442a393c4699037d9f957'



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


def send_sendgrid_broadcast_email(mail_list, email_message,queryParam):
    """
        Description: This will send an email with a message coming from the admin that will reach a particular
        audience.
    """

    template_data ={"email_message":email_message, "unsubscribe_link":UNSUBSCRIBE_URL}
    
    print(mail_list)
    message = Mail(
        from_email=SOURCE_EMAIL,
        to_emails=list(map(To, mail_list)),
    )
    message.dynamic_template_data = template_data
    message.template_id = SENDGRID_NOTIFICATION_TEMPLATE_ID

    sendgrid_client = SendGridAPIClient(SENDGRID_API_KEY)
    response = sendgrid_client.send(message)

def send_sendgrid_unsubscribe_email(to_user):
    """
        Description: send email to actually subscribe and hit the endpoint.
        use dateJoined as the PRIMARY KEY TO LOOKUP EACH USER IN THE TABLE.
    """
    

    template_data = {"unsubscribe_link": f"{UNSUBSCRIBE_URL}/{to_user['dateJoined']}"}
    
    print('sending unsubscribe email', to_user)
    message = Mail(
        from_email=SOURCE_EMAIL,
        to_emails=[To(to_user['email'])],
    )
    message.dynamic_template_data = template_data
    message.template_id = SENDGRID_UNSUBSCRIBE_TEMPLATE_ID

    sendgrid_client = SendGridAPIClient(SENDGRID_API_KEY)
    response = sendgrid_client.send(message)

    return send_response(status=200, body={"data":"Successfully sent unsubscribe email"})
    

def send_sendgrid_event_email(gathering, mail_list):
    """
        Description: Send an ses email to all users who are currently subscribed to the site.
        This is only for when NEW EVENTS are created, we want to notify all subscribed users of the newly created event.
    """
    # NOTE: Please format the date accordingly
    print('in send_sendgrid_event_email')
    start_date = datetime.fromisoformat(gathering['date'])
    destination_addresses = list(map(lambda user: To(user['email']), mail_list))
    print('before template_data')
    
    template_data={
        "start_date":f"{days[start_date.weekday()]}, {months[start_date.month-1]} {start_date.day}",#"Friday, May 14", 
        "location":f"{gathering['location']}",#"117 West Windsor Ave, Lombard IL", 
        "start_time":f"{get_formatted_hour(gathering['date'])[:-2]}", #"7pm",
        "end_time":f"{get_formatted_hour(gathering['timeEnd'])}",#9pm
        "extra_details":f"{gathering['extraRequests']}",#"Food and drinks will be provided."
        "unsubscribe_link":UNSUBSCRIBE_URL#Direct them to unsubscribe portal
    }
    print('template data', destination_addresses)


    message = Mail(
        from_email=SOURCE_EMAIL,
        to_emails=destination_addresses
    )
    message.dynamic_template_data = template_data
    message.template_id = SENDGRID_EVENT_TEMPLATE_ID

    sendgrid_client = SendGridAPIClient(SENDGRID_API_KEY)
    response = sendgrid_client.send(message)

    print('sent emails')


def event_notify():
    """
        Description: Notify ALL site subscribers about EVENT that is happening.
    """
    print('in event notify')
    gathering_response = dynamodb.Table('ifawf-gathering').query(**global_gathering_query)
    gathering = gathering_response['Items'][0]
    site_subscribers_response = dynamodb.Table('ifawf-subscribers').scan(
        Limit=100
    )
    email_list = []
    for user in site_subscribers_response['Items']:
        email_list.append(user)
    
    print('email_list', email_list)
    send_sendgrid_event_email(gathering=gathering, mail_list=email_list)

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
            send_sendgrid_event_email(gathering=gathering,mail_list=email_list)
    return send_response(status=200, body={"data":"successfully sent email?"})


    
def email_unsubscribe(event):
    """
        Description: find the user in either of the tables.
        User will enter their email in the unsubscribe box and this endpoint 
        function will be triggered. A confirmation email will be sent to redirect the user
        to a site endpoint which will then call the unsubscribe endpoint which will then 
        remove the user from all forms of communication.
    """
    body = json.loads(event['body'])
    if validate_body(expected_keys=['email'], event=body) == False:
        return BAD_REQUEST
    
    fetch_email_user_query = {
        "TableName": "ifawf-subscribers",
        "KeyConditionExpression":"#email = :email",
        "ScanIndexForward":False,
        "ExpressionAttributeValues": {
        ":email":body['email'],  
        },
        "ExpressionAttributeNames": {
            "#email":"email"
        },
        "Limit": 1
    }

    # Fetch the user and check if they exist in the site subscribers table. If so, send them an email from here
    fetched_user = dynamodb.Table('ifawf-subscribers').query(**fetch_email_user_query)
    if len(fetched_user['Items']) != 0:
        return send_sendgrid_unsubscribe_email(to_user=fetched_user['Items'][0])
    

    # IF the user does not have site subscription, check if they are subscribed to an event.
    # if so, then send them an email to unsubscribe to the event.
    # Grab the event as primary key for the event subscriber table.
    fetched_event = dynamodb.Table('ifawf-gathering').query(**global_gathering_query)
    if len(fetched_event['Items']) == 0:
        return send_response(status=204, body={"data":"No current event"})
    current_event = fetched_event['Items'][0]

    # Now we fetch the user with the primary key taken from the current event
    fetched_user = dynamodb.Table('ifawf-event-subscribers').get_item(
        Key={'eventid':current_event['created'], 'email':body['email']}
    )

    # if user does not exist in events table, send 204 since they don't exist.
    if 'Item' not in fetched_user:
        return send_response(status=204, body={"data":"User does not exist"})
    
    # Send the unsubscribe email to the user
    return send_sendgrid_unsubscribe_email(to_user=fetched_user['Item'])
    



def email_subscribers(event,table):
    """
        Description: Grab all users from the desired table 'ifawf-event-subscribers' | 'ifawf-subscribers'
        and send them a custom message provided in the body. This is used if you want to broadcast a message to 
        people in the site. This is not an invitation.
    """
    subscribers_response = dynamodb.Table(table).scan(
        Limit=100
    )
    email_list = []
    for user in subscribers_response['Items']:
        email_list.append(user['email'])
    
    queryParam = 'all'

    if table=='ifawf-event-subscribers':
        queryParam='event'

    body=json.loads(event['body'])

    send_sendgrid_broadcast_email(mail_list=email_list, email_message=body['message'], queryParam=queryParam)
    
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
            send_sendgrid_broadcast_email(mail_list=email_list, email_message=body['message'], queryParam=queryParam)
    
    return send_response(status=200, body={"data":"Successfully notified users!"})


def lambda_handler(event, context):
    """
        
    """
    try:
        if 'type' not in event['queryStringParameters']:
            return BAD_REQUEST
        q = event['queryStringParameters']
        
        if q['type'] == 'unsubscribe':
            return email_unsubscribe(event=event)
        
        # Any further action the user must be unsubscribed.
        if validate_auth(event['headers']) == False:
            return NOT_AUTH
        print("EVENT", event)
        
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
    except Exception as e:
        print(str(e), "Sending 500 response")
        return send_response(500,{"data":"Internal Server error"})