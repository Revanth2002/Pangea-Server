import requests
from django.conf import settings
import hashlib
import hmac
import base64


CASHFREE_APPID="10561330d5f13885191bd786ff316501"
CASHFREE_SECRET="c4ed3ae9a37ef89c4143b611168b8ea0d9e2d484"
CASHFREE_PRODUCTION_URL="https://api.cashfree.com/api/v2/cftoken/order"
CASHFREE_TEST_URL="https://test.cashfree.com/api/v2/cftoken/order"

URL=settings.CASHFREE_TEST_URL
#URL=settings.CASHFREE_PRODUCTION_URL
APPID=settings.CASHFREE_APPID
SECRET=settings.CASHFREE_SECRET

def process_payment(orderid,amount):
	
	header={
		"Content-Type":"application/json",
		"x-api-version":"2021-05-21",
		"x-client-id":APPID,
		"x-client-secret":SECRET
	}

	data="""{"orderId":"%s","orderAmount":%f,"orderCurrency":"INR"}"""%(orderid,amount)


	
	r=requests.post(URL,data=data,headers=header)

	return r.json()["cftoken"]



def verify_payment(**kwargs):
	
	
	postData = {
			"orderId" : kwargs['orderId'], 
			"orderAmount" : kwargs['orderAmount'], 
			"referenceId" : kwargs['referenceId'], 
			"txStatus" : kwargs['txStatus'], 
			"paymentMode" : kwargs['paymentMode'], 
			"txMsg" : kwargs['txMsg'], 
			"txTime" : kwargs['txTime'], 
	}
	signatureData=""
	for i in postData.keys():
		signatureData=signatureData+postData[i]

	message=bytes(signatureData).encode('utf-8')
	secret=bytes(SECRET).encode('utf-8')
	signature = base64.b64encode(hmac.new(secret,message,digestmod=hashlib.sha256).digest())

	if signature==kwargs["signature"]:
		return True
	return False