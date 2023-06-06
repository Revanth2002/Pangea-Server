from twilio.rest import Client
from django.conf import settings
import requests
import urllib.parse

# Your Account SID and Auth Token from twilio.com/console
account_sid = settings.TWILIO_ACCOUNT_SID
auth_token = settings.TWILIO_AUTH_TOKEN
client = Client(account_sid, auth_token)

MSG91_AUTH_KEY = settings.MSG91_AUTH_KEY
MSG91_DLT_TE_ID = settings.MSG91_DLT_TE_ID

def send_sms_to_mobile_via_twilio(message,mobile):
    try:
        string_to_encode = message
        encoded_string = urllib.parse.quote(string_to_encode)

        url = "https://api.msg91.com/api/v5/flow/"
        headers = {
            "Content-Type": "application/json",
            "authkey": "362057A6plW2WJ60bdae16P1",
            'accept': 'application/json'
        }
        payload = {
            "template_id": "647f413ed6fc0508312c47e2",
            "sender": "123456",
            "mobiles": mobile,
            "schtime": "",
            "params": {
                "message": message
            }
        }
        send_sms = requests.post(url, headers=headers, json=payload)

        # url = f"https://api.msg91.com/api/sendhttp.php?sender=ZeroPay&route=4&mobiles=+91{mobile}&authkey={MSG91_AUTH_KEY}&DLT_TE_ID={MSG91_DLT_TE_ID}&country=0&message={str(encoded_string)}"
        # print(url)

        # url = "https://api.msg91.com/api/sendhttp.php?sender=HOTNOT&route=4&mobiles=+91" + mobile + "&authkey=" + MSG91_AUTH_KEY+"&DLT_TE_ID="+MSG91_DLT_TE_ID+"&country=0&message=%3C%23%3E%20Your%20HotNot%20account%20verification%20OTP%20code%20is%20" + str(
        # 12345) + "%20.%20Please%20DO%20NOT%20share%20this%20OTP%20with%20anyone.%20UYn59TTDkhp"
        # payload = {}
        # headers = {
        #     'Cookie': 'PHPSESSID=q4tlbic4lv0510dr4h6qeabsn5'
        # }
        # send_sms = requests.request("GET", url, headers=headers, data=payload)
        print(send_sms)

        content = {
            'message': 'OTP sent',
            'status': 1,
        }
        return True
    except Exception as e:
        print(e)
        return False

def send_sms_to_mobile(message, mobile):
    if mobile not in ["8072195191","8610791036"]:
        return False
    try:
        res = client.messages.create(
            body=message,
            from_= "+13203503142", #'+13203503142',
            to=f'+91{mobile}' # mobile #
        )
        print(res.sid)      
        return True
    except Exception as e:
        print(e)
        return False
    
