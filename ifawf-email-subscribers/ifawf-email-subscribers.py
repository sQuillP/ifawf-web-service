import json
import boto3
import jwt
from datetime import datetime, date, timedelta


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
UNSUBSCRIBE_TEMPLATE='ifawf_unsubscribe'
BASE_URL='http://indyfaithandworkforum.org'



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


def send_ses_message_email(mail_list, email_message,queryParam):
    """
        Description: Calls boto3 ses api for sending emails to many users.
    """

    template_data ={"email_message":email_message, "unsubscribe_link":f"http://localhost:3000/unsubscribe?type={queryParam}"}
    ses.send_templated_email(
        Source=SOURCE_EMAIL,
        Destination={
            "ToAddresses":[SOURCE_EMAIL]
        },
        ReplyToAddresses=[SOURCE_EMAIL],
        Template=MESSAGE_TEMPLATE,
        TemplateData=json.dumps(template_data)
    )


def send_ses_unsubscribe_email(to_user):
    """
        Description: send email to actually subscribe and hit the endpoint.
    """
    

    template_data = {"unsubscribe_link": f"http://localhost:3000/unsubscribe/{to_user['dateJoined']}"}
    
    ses.send_template_email(
        Source=SOURCE_EMAIL,
        Destination={
            "ToAddresses":[SOURCE_EMAIL]
        },
        Template=UNSUBSCRIBE_TEMPLATE,
        TemplateData=json.dumps(template_data)
    )
    pass
    

def send_ses_event_email(gathering, mail_list):
    """
        Description: Send an ses email to all users who are currently subscribed to the site.
        This is only for when NEW EVENTS are created, we want to notify all subscribed users of the newly created event.
    """
    # NOTE: Please format the date accordingly
    start_date = datetime.fromisoformat(gathering['date'])
    destination_addresses = map(lambda user: user['email'], mail_list)

    template_data={
        "start_date":f"{days[start_date.weekday()]}, {months[start_date.month-1]} {start_date.day}",#"Friday, May 14", 
        "location":f"{gathering['location']}",#"117 West Windsor Ave, Lombard IL", 
        "start_time":f"{get_formatted_hour(gathering['date'])[:-2]}", #"7pm",
        "end_time":f"{get_formatted_hour(gathering['timeEnd'])}",#9pm
        "extra_details":f"{gathering['extraRequests']}",#"Food and drinks will be provided."
        "unsubscribe_link":"http://localhost:3000/unsubscribe?type=all"
    }


    ses.send_templated_email(
        Source=SOURCE_EMAIL,
        Destination={
            "ToAddresses":[SOURCE_EMAIL] #destination_addresses
        },
        ReplyToAddresses=[SOURCE_EMAIL],
        Template=NOTIFY_TEMPLATE,
        TemplateData=json.dumps(template_data)
    )


def event_notify():
    """
        Description: Notify ALL site subscribers about EVENT that is happening.
    """
    gathering_response = dynamodb.Table('ifawf-gathering').query(**global_gathering_query)
    gathering = gathering_response['Items'][0]
    site_subscribers_response = dynamodb.Table('ifawf-subscribers').scan(
        Limit=100
    )
    email_list = []
    for user in site_subscribers_response['Items']:
        email_list.append(user)
    
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
        and send them a custom message provided in the body.
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

    send_ses_message_email(mail_list=email_list, email_message=body['message'], queryParam=queryParam)
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
            send_ses_message_email(mail_list=email_list, email_message=body['message'], queryParam=queryParam)
    
    return send_response(status=200, body={"data":"Successfully notified users!"})


def lambda_handler(event, context):
    """
        
    """
    try:
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
    except:
        return send_response(500,{"data":"Internal Server error"})