from twilio.rest import Client
from django.conf import settings

# Your Account SID and Auth Token from twilio.com/console
account_sid = settings.TWILIO_ACCOUNT_SID
auth_token = settings.TWILIO_AUTH_TOKEN
client = Client(account_sid, auth_token)

def send_sms_to_mobile(message, mobile):
    try:
        res = client.messages.create(
            body=message,
            from_='+13203503142',
            to= mobile #'+918072195191'
        )
        print(res.sid)      
        return True
    except Exception as e:
        print(e)
        return False