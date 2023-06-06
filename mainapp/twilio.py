from twilio.rest import Client
from django.conf import settings
import requests

# Your Account SID and Auth Token from twilio.com/console
account_sid = settings.TWILIO_ACCOUNT_SID
auth_token = settings.TWILIO_AUTH_TOKEN
client = Client(account_sid, auth_token)

MSG91_AUTH_KEY = settings.MSG91_AUTH_KEY
MSG91_DLT_TE_ID = settings.MSG91_DLT_TE_ID

def send_sms_to_mobile(message,mobile):
    try:
        url = "https://api.msg91.com/api/sendhttp.php?sender=HOTNOT&route=4&mobiles=+91" + mobile + "&authkey=" + MSG91_AUTH_KEY+"&DLT_TE_ID="+MSG91_DLT_TE_ID+"&country=0&message=" + message
        print(url)
        payload = {}
        headers = {
            'Cookie': 'PHPSESSID=q4tlbic4lv0510dr4h6qeabsn5'
        }
        send_sms = requests.request("GET", url, headers=headers, data=payload)
        print(send_sms)
        content = {
            'message': 'OTP sent',
            'status': 1,
        }
        return True
    except Exception as e:
        print(e)
        return False

def send_sms_to_mobile_via_twilio(message, mobile):
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
    
