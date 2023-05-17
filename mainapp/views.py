from django.shortcuts import render
import random
from datetime import datetime as dtt, time, date, timedelta
import json
import requests
import uuid
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from pangeaserver.responsecode import display_response
from django.db.models import Q
from django.conf import settings

from .views import *
from .models import *
from .serializers import *
from pangeaserver.utils import *
from pangeaserver.auth import UserAuthentication
from .pangea import make_auditlog,redact_text,ip_geolocate,ip_reputation,user_email_breached_check,encrypt_vault,decrypt_vault
from .twilio import send_sms_to_mobile

APP_NAME_TEXT = "ZeroPay"
ZPAY_PIN_VAULT = "zp_pin_vault"
PASSWORD_VAULT = "zp_password_vault"


def create_notification(pid,title,msg):
    try:
        notif_instance = NotificationModel.objects.create(
            pid=pid,
            title=title,
            message=msg
        )
        notif_instance.save()
        return True
    except Exception as e:
        print(e)
        return False


# --------Login/Register API--------
"""
    This view is responsible for both login and register of the user.
    For Login :
        - Send mobile number to the server and if pid is returned then enter the login pin
    For Register :
        - Send email,password and create user
        - Send name,mobile and update the create user
"""

class LoginUser(APIView):

    """
        This view is responsible for both login and register of the user
        If the user is new then he is registered in the database

        methods:
            -POST

        POST data:mobile number of the user

        return: accesstoken

    """

    authentication_classes = []
    permission_classes = []

    def post(self, request, fromat=None):

        data = request.data

        number = data.get("number", None)

        # validating the mobile number
        if number in ["", None] or len(number) != 10:
            return Response({
                "MSG": "FAIL",
                "ERR": "Please provided user data(mobile number)",
                "BODY": None
            }, status=status.HTTP_404_NOT_FOUND)

        #PANGEA-IPREPUTATION
        """If the IP verdict is malicious then block the user"""
        ip_address = request.META.get('REMOTE_ADDR')
        check_ip = ip_reputation(ip_address)
        if check_ip['status'] == 'success':
            if check_ip['body']['verdict'] == 'malicious':
                return display_response(
                    msg="FAIL",
                    err="Login failed. Malicious IP Found",
                    body=None,
                    statuscode=status.HTTP_404_NOT_FOUND
                )
        else:
            return display_response(
                msg="FAIL",
                err="Login failed. Malicious IP Found",
                body=None,
                statuscode=status.HTTP_404_NOT_FOUND
            )

        # gets the userinstance in case of old user or creates a new user instance
        user_instance = UserModel.objects.filter(mobile=number).first()
        if user_instance is None:
            return display_response(
                msg="FAIL",
                err="User does not exist.Try signup",
                body=None,
                statuscode=status.HTTP_404_NOT_FOUND
            )

        """Generate a otp and send to the user"""
        get_otp_instance = UserOTPModel.objects.get_or_create(pid=user_instance.pid)[0]
        """Generate a random 6 digits number"""

        if number == "9876543210":
            otp = "123456"
        else:
            otp = random.randint(100000, 999999)
        get_otp_instance.otp = otp
        get_otp_instance.save()
        print("------OTP------")
        print(otp)
        try:
            txt_temp = f"Your {APP_NAME_TEXT} login OTP for {user_instance.mobile} is {otp}"
            #PANGEA-REDACT
            redact_res = redact_text(txt_temp)
            if redact_res["status"] == "success":
                txt_temp = redact_res["body"]
                try:
                    """Send the otp to the user"""
                    # twilio_res = send_sms_to_mobile(txt_temp, user_instance.mobile)
                    print(txt_temp)
                    twilio_res = "success"
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)

        return display_response(
            msg="SUCCESS",
            err=None,
            body={
                "pid": user_instance.pid,
            },
            statuscode=status.HTTP_200_OK
        )


class EnterLoginPin(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request, fromat=None):
        data = request.data
        pid = data.get("pid", None)
        otp = data.get("otp", None)

        if pid in ["", None] or otp in ["", None]:
            return display_response(
                msg="FAIL",
                err="Please provide user data",
                body=None,
                statuscode=status.HTTP_404_NOT_FOUND
            )



        user_instance = UserModel.objects.filter(pid=pid).first()
        if user_instance is None:
            return display_response(
                msg="FAIL",
                err="User does not exist.Try signup",
                body=None,
                statuscode=status.HTTP_404_NOT_FOUND
            )

        """Check if the otp matches"""
        get_otp_instance = UserOTPModel.objects.filter(pid=user_instance.pid).first()
        if get_otp_instance is None:
            return display_response(
                msg="FAIL",
                err="OTP does not exist",
                body=None,
                statuscode=status.HTTP_404_NOT_FOUND
            )
        if get_otp_instance.otp != otp:
            return display_response(
                msg="FAIL",
                err="Invalid OTP",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )

        """---Decrypt the cipher password and send to the server---"""
        #PANGEA_DECRYPTION_PIN
        # pass_decrypt = decrypt_vault(user_instance.password,PASSWORD_VAULT)
        # print("--------------")
        # print(pass_decrypt)
        # if pass_decrypt['status'] != "success":
        #     return display_response(
        #         msg="FAIL",
        #         err="Something went wrong in newpin encryption",
        #         body=None,
        #         statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR
        #     )
        # password_plain = pass_decrypt['body']['plain_text']
        print("----credits----")
        print(user_instance.email)
        print(user_instance.password)
        payload = {
            "email": user_instance.email,
            "password": user_instance.password
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {settings.PANGEA_API_KEY}",
        }
        api_endpoint_url = "https://authn.aws.us.pangea.cloud/v1/user/login/password"
        response = requests.post(
            api_endpoint_url, json=payload, headers=headers)
        print(response.status_code)
        if response.status_code == 200:
            # Request was successful
            print(response.json())

            if response.json()['result'] == None:
                return display_response(
                    msg="FAIL",
                    err="Invalid pin",
                    body=None,
                    statuscode=status.HTTP_404_NOT_FOUND
                )

            return display_response(
                msg="SUCCESS",
                err=None,
                body={
                    "access_token": response.json()["result"]['active_token']['token'],
                    "refresh_token": response.json()["result"]['refresh_token']['token'],
                    "pid": pid
                },
                statuscode=status.HTTP_200_OK
            )
        else:
            # Request failed
            print("Error:", response.status_code)
            return display_response(
                msg="FAIL",
                err="Invalid pin",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )


class RegisterUser(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request, fromat=None):
        data = request.data
        email = data.get("email", None)
        mobile = data.get("number", None)
        username = data.get("username", None)
        # password = data.get("password", None)

        if email in ["", None] or mobile in ["", None] or username in ["", None]:
            return display_response(
                msg="FAIL",
                err="Please provide user data",
                body=None,
                statuscode=status.HTTP_400_BAD_REQUEST
            )

        breached_check = user_email_breached_check(email)
        if breached_check['status'] == 'success':
            if breached_check['body']['breached'] == True:
                return display_response(
                    msg="FAIL",
                    err="Email has been breached.Try new email",
                    body=None,
                    statuscode=status.HTTP_406_NOT_ACCEPTABLE
                )

        # check if user already exists
        user_instance = UserModel.objects.filter(email=email).first()
        if user_instance is not None:
            return display_response(
                msg="FAIL",
                err="User already exists",
                body=None,
                statuscode=status.HTTP_409_CONFLICT
            )

        """Generate a random password"""
        random_uuid = uuid.uuid4()
        random_password = str(random_uuid).replace('-', '')[0:10]
        print(random_password)
   
        """Encrypt the password"""
        pass_encrypt = encrypt_vault(random_password,PASSWORD_VAULT)
        print("-------Password Encrypt-------")
        print(pass_encrypt)
        if pass_encrypt['status'] != "success":
            return display_response(
                msg="FAIL",
                err="Something went wrong in password encryption",
                body=None,
                statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        password_cipher = pass_encrypt['body']['cipher_text']
        print("----cipher text-----")
        print(password_cipher)
        api_endpoint_url = "https://authn.aws.us.pangea.cloud/v1/user/create"
        payload = {
            "email": email, 
            "authenticator": password_cipher, 
            "profile":{
                "first_name":username,
                "phone":mobile
            },
            "id_provider": "password",
            "verified": True
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {settings.PANGEA_API_KEY}",
        }

        response = requests.post(api_endpoint_url, json=payload, headers=headers)
        print("---Create user response---")
        print(response.json())
        if response.status_code == 200:
            #create user in our database
            user_instance = UserModel.objects.create(
                email=email,
                pid=response.json()["result"]["id"],
                mobile=mobile,
                name=username,
                password=password_cipher
            )
            user_instance.save()

            #create a 6 digit otp for the user
            if mobile == "9876543210":
                otp = "123456"
            else:
                otp = random.randint(100000, 999999)
            print(otp)
            otp_instance = UserOTPModel.objects.create(
                otp=otp,
                pid=user_instance.pid
            )

            return display_response(
                msg="SUCCESS",
                err=None,
                body={
                    "pid": user_instance.pid,
                },
                statuscode=status.HTTP_200_OK
            )
        else:
            # Request failed
            print("Error:", response.status_code)
            return display_response(
                msg="FAIL",
                err="Invalid pin",
                body=None,
                statuscode=status.HTTP_400_BAD_REQUEST
            )
        
class UpdateUserInfo(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request, fromat=None):
        data = request.data
        pid = data.get("pid", None)
        name = data.get("name", None)
        mobile = data.get("mobile", None)

        if pid in ["", None] or name in ["", None] or mobile in ["", None]:
            return display_response(
                msg="FAIL",
                err="Please provide user data",
                body=None,
                statuscode=status.HTTP_400_BAD_REQUEST
            )
        
        user_instance = UserModel.objects.filter(pid=pid).first()
        if user_instance is None:
            return display_response(
                msg="FAIL",
                err="User does not exist.Try signup",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )
        
        user_instance.name = name
        user_instance.mobile = mobile
        user_instance.save()

        #save the username and mobile in pangae api
        api_endpoint_url = f"https://authn.aws.us.pangea.cloud/v1/user/profile/update"
        payload = {
            "email":user_instance.email,
           "profile":{
                "first_name":name,
                "phone":mobile
                } 
            }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {settings.PANGEA_API_KEY}",
        }
        response = requests.post(api_endpoint_url, json=payload, headers=headers)
        if response.status_code == 200:
            return display_response(
                msg="SUCCESS",
                err=None,
                body={
                    "pid": user_instance.pid,
                },
                statuscode=status.HTTP_200_OK
            )
        else:
            # Request failed
            print("Error:", response.status_code)
            return display_response(
                msg="FAIL",
                err="Invalid pin",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )

#-----Add Card API-----
class AddCard(APIView):
    authentication_classes = [UserAuthentication]
    permission_classes = []

    def post(self, request, fromat=None):
        user=request.user
        data = request.data

        print(user)

        pid = user.pid
        card_number = data.get("card_number", None)
        card_expiry = data.get("expiry_month", None)
        card_cvv = data.get("cvv", None)
        card_holder_name = data.get("card_holder_name", None)
                
        if pid in ["", None] or card_number in ["", None] or card_expiry in ["", None] or card_cvv in ["", None] or card_holder_name in ["", None]:
            return display_response(
                msg="FAIL",
                err="Please provide card data",
                body=None,
                statuscode=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            card_instance = AddedCardsModel.objects.create(
                pid=pid,
                card_number=card_number,
                card_expiry=card_expiry,
                card_cvv=card_cvv,
                card_holder_name=card_holder_name,
                total_balance=10000
            )
            card_instance.save()
            return display_response(    
                msg="SUCCESS",
                err=None,
                body={
                    "pid": card_instance.pid,
                },
                statuscode=status.HTTP_200_OK
            )
        except Exception as e:
            print(e)
            return display_response(
                msg="FAIL",
                err="Invalid pin",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )

class GetCards(APIView):
    authentication_classes = [UserAuthentication]
    permission_classes = []

    def get(self, request):
        user=request.user
        pid = user.pid
        card_instances = AddedCardsModel.objects.filter(pid=pid)
        if card_instances is None:
            return display_response(
                msg="FAIL",
                err="User does not exist.Try signup",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )
        cards = []
        for card_instance in card_instances:
            cards.append({
                "card_number": card_instance.card_number,
                "card_expiry": card_instance.card_expiry,
                "card_cvv": card_instance.card_cvv,
                "card_holder_name": card_instance.card_holder_name,
                "total_balance": card_instance.total_balance,
                "bank_name" : card_instance.bank_name,
                "is_verified": card_instance.is_verified,
                "is_active": card_instance.is_active,
                "img": "https://www.cardexpert.in/wp-content/uploads/2022/02/axis-atlas-banner.png"
            })
        return display_response(
            msg="SUCCESS",
            err=None,
            body={
                "pid": pid,
                "cards": cards,
                "total_cards": len(cards)
            },
            statuscode=status.HTTP_200_OK
        )


class MyProfile(APIView):
    authentication_classes = [UserAuthentication]
    permission_classes = []

    def get(self, request, fromat=None):
        user=request.user
        pid = user.pid
        user_instance = UserModel.objects.filter(pid=pid).first()
        if user_instance is None:
            return display_response(
                msg="FAIL",
                err="User does not exist.Try signup",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )

        return display_response(
            msg="SUCCESS",
            err=None,
            body={
                "pid": user_instance.pid,
                "name": user_instance.name,
                "email": user_instance.email,
                "mobile": user_instance.mobile,
                "pin_set": user_instance.is_pin_set
            },
            statuscode=status.HTTP_200_OK
        )
    
class PeopleTranscations(APIView):
    authentication_classes = [UserAuthentication]
    permission_classes = []

    def get(self, request, fromat=None):
        user=request.user
        data = request.query_params
        pid = user.pid
        to_pid = data.get("to_pid", None)

        print("----------------")
        print(user.is_pin_set)
        json_data = {
            "to_pid":{},
            "transactions" : [],
            "is_pin_set" : user.is_pin_set,
            "card_enabled" :False,
            "card_number" : "",
        }

        if pid in ["", None] or to_pid in ["", None]:
            return display_response(
                msg="FAIL",
                err="Please provide user data",
                body=None,
                statuscode=status.HTTP_400_BAD_REQUEST
            )

        """current user data card checking"""
        card_instance = AddedCardsModel.objects.filter(pid=pid).first()
        if card_instance is not None:
            json_data["card_enabled"] = card_instance.is_verified
            json_data["card_number"] = card_instance.card_number

        user_instance = UserModel.objects.filter(pid=to_pid).first()
        if user_instance is None:
            return display_response(
                msg="FAIL",
                err="User does not exist.Try signup",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )
        
        receiver_card = AddedCardsModel.objects.filter(pid=to_pid).first()

        json_data["to_pid"] = {
            "pid": user_instance.pid,
            "name": user_instance.name,
            "email": user_instance.email,
            "mobile": user_instance.mobile,
            "img": "https://www.cardexpert.in/wp-content/uploads/2022/02/axis-atlas-banner.png",
            "card_enabled": receiver_card.is_verified,
        }


        transactions = TransactionModel.objects.filter(Q(from_pid=pid) | Q(to_pid=pid)).order_by('-created_at')
        serializer = TransactionSerializer(transactions, many=True, context={"request": request})
        for t in serializer.data:
            own_pid = True #Received
            if(t['from_pid'] == pid):
                own_pid = False #Sent
                user_instance = UserModel.objects.filter(pid=t['to_pid']).first()
            else:
                user_instance = UserModel.objects.filter(pid=t['from_pid']).first()

            json_data["transactions"].append({
                "pid": user_instance.pid,
                "name": user_instance.name,
                "email": user_instance.email,
                "mobile": user_instance.mobile,
                "img": "https://www.cardexpert.in/wp-content/uploads/2022/02/axis-atlas-banner.png",
                "own_pid": own_pid,
                "transaction_type": t['transaction_type'],
                "transaction_id": t['transaction_id'],
                "amount": t['amount'],
                "transaction_status": t['transaction_status'],
                "created_at": dtt.strptime(t['created_at'] , YmdTHMSfz).strftime(dBYIMp)
            })

            

        return display_response(
            msg="SUCCESS",
            err=None,
            body=json_data,
            statuscode=status.HTTP_200_OK
        )

class AllTransactions(APIView):
    authentication_classes = [UserAuthentication]
    permission_classes = []

    def get(self, request):
        user=request.user
        pid = user.pid

        json_data = {
            "transactions" : []
        }

        transactions = TransactionModel.objects.filter(Q(from_pid=pid) | Q(to_pid=pid)).order_by('-created_at')
        for t in transactions:
            own_pid = True #Received
            if(t.from_pid == pid):
                own_pid = False #Sent
                user_instance = UserModel.objects.filter(pid=t.to_pid).first()
            else:
                user_instance = UserModel.objects.filter(pid=t.from_pid).first()

            json_data["transactions"].append({
                "pid": user_instance.pid,
                "name": user_instance.name,
                "email": user_instance.email,
                "mobile": user_instance.mobile,
                "img": "https://www.cardexpert.in/wp-content/uploads/2022/02/axis-atlas-banner.png",
                "own_pid": own_pid,
                "transaction_type": t.transaction_type,
                "transaction_id": t.transaction_id,
                "amount": t.amount,
                "transaction_status": t.transaction_status
            })

        return display_response(
            msg="SUCCESS",
            err=None,
            body=json_data,
            statuscode=status.HTTP_200_OK
        )


class HomeScreen(APIView):
    authentication_classes = [UserAuthentication]
    permission_classes = []

    def get(self, request,format=None):
        user=request.user
        pid = user.pid
        user_instance = UserModel.objects.filter(pid=pid).first()
        if user_instance is None:
            return display_response(
                msg="FAIL",
                err="User does not exist.Try signup",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )

        json_data = {
            "pid": user_instance.pid,
            "name": user_instance.name,
            "email": user_instance.email,
            "mobile": user_instance.mobile,
            "img" : "https://images.pexels.com/photos/771742/pexels-photo-771742.jpeg?auto=compress&cs=tinysrgb&dpr=1&w=500",
            "cards":[],
            "people":[],
            "is_card_added": True,
            "is_pin_set": user.is_pin_set,
            "primary_card" : {},
            "cards_count": 0,
            "people_count": 0,
            "last_promotional_img" : "https://appbeep.com/wp-content/uploads/2018/04/PhonePe.png"
        }

        cards = AddedCardsModel.objects.filter(Q(pid=pid)).order_by("-created_at")
        print("--------------------")
        print(len(cards))
        if len(cards) != 0:
            json_data["primary_card"] = {
                "card_type" : cards[0].card_type,
                "card_number": cards[0].card_number,
                "card_expiry": cards[0].card_expiry,
                "card_holder_name": cards[0].card_holder_name,
                "total_balance": cards[0].total_balance,
                "card_cvv": cards[0].card_cvv,
                "total_balance": cards[0].total_balance,
                "bank_name": cards[0].bank_name,
                "is_verified": cards[0].is_verified,
                "is_active": cards[0].is_active,
                "card_img" : "https://www.cardexpert.in/wp-content/uploads/2022/02/axis-atlas-banner.png"
            }

        for card in cards:
            json_data["cards"].append({
                "card_type" : card.card_type,
                "card_number": card.card_number,
                "card_expiry": card.card_expiry,
                "card_holder_name": card.card_holder_name,
                "total_balance": card.total_balance,
                "card_cvv": card.card_cvv,
                "total_balance": card.total_balance,
                "bank_name": card.bank_name,
                "is_verified": card.is_verified,
                "is_active": card.is_active
            })

        if len(json_data["cards"]) == 0:
            json_data["is_card_added"] = False

        people = TransactionModel.objects.filter(from_pid=pid).values("to_pid").distinct()
        for person in people:
            person_instance = UserModel.objects.filter(pid=person["to_pid"]).first()
            json_data["people"].append({
                "pid": person_instance.pid,
                "name": person_instance.name,
                "email": person_instance.email,
                "mobile": person_instance.mobile,
                "img" : "https://shotkit.com/wp-content/uploads/2021/06/cool-profile-pic-matheus-ferrero.jpeg"
            })

        json_data["cards_count"] = len(json_data["cards"])
        json_data["people_count"] = len(json_data["people"])

        return display_response(
            msg="SUCCESS",
            err=None,
            body=json_data,
            statuscode=status.HTTP_200_OK
        )

#-----Send Payments-----
class SendPayment(APIView):
    authentication_classes = [UserAuthentication]
    permission_classes = []

    def post(self, request, format=None):
        data = request.data
        user=request.user

        pid = user.pid
        to_pid = data.get("to_pid", None)
        amount = data.get("amount", None)
        pin = data.get("pin", None)

        if pid in ["", None] or to_pid in ["", None] or amount in ["", None] or pin in ["", None]:
            return display_response(
                msg="FAIL",
                err="Please provide user data",
                body=None,
                statuscode=status.HTTP_400_BAD_REQUEST
            )

        amount = float(amount)
        user_instance = UserModel.objects.filter(pid=to_pid).first()
        if user_instance is None:
            return display_response(
                msg="FAIL",
                err="User does not exist.Try signup",
                body=None,
                statuscode=status.HTTP_404_NOT_FOUND
            )

        # #PANGEA_ENCRYPTION_PIN
        # new_pin_encrypt = encrypt_vault(pin,ZPAY_PIN_VAULT)
        # if new_pin_encrypt['status'] != "success":
        #     return display_response(
        #         msg="FAIL",
        #         err="Something went wrong in newpin encryption",
        #         body=None,
        #         statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR
        #     )
        # cipher_new_pin = new_pin_encrypt['body']['cipher_text']
        # print(pin)
        # print("-------Pin Part---------")
        # print(user_instance.pin)
        # print(cipher_new_pin)

        #PANGAEA_DECRYPTION_PIN
        pin_decrypt = decrypt_vault(user_instance.pin,ZPAY_PIN_VAULT)
        if pin_decrypt['status'] != "success":
            return display_response(
                msg="FAIL",
                err="Something went wrong in pin decryption",
                body=None,
                statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        plain_pin = pin_decrypt['body']['plain_text']
        print(plain_pin)

        """User Pin Checking"""
        if pin != plain_pin:
            return display_response(
                msg="FAIL",
                err="Pin is incorrect",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )

        receiver_card_instance = AddedCardsModel.objects.filter(pid=to_pid).first()
        if receiver_card_instance is None:
            return display_response(
                msg="FAIL",
                err="User card does not exist",
                body=None,
                statuscode=status.HTTP_404_NOT_FOUND
            )
        

        card_instance = AddedCardsModel.objects.filter(pid=user.pid).first()
        if card_instance is None:
            return display_response(
                msg="FAIL",
                err="Card does not exist",
                body=None,
                statuscode=status.HTTP_404_NOT_FOUND
            )
        
        """check if the card has sufficient balance"""
        if card_instance.total_balance < amount:
            return display_response(
                msg="FAIL",
                err="Insufficient balance",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )


        """Create transcation object"""
        transcation_id = str(uuid.uuid4())
        transcation_instance = TransactionModel.objects.create(
            from_pid=pid,
            to_pid=to_pid,
            amount=amount,
            card_id=card_instance.id,
            transaction_type="SEND",
            transaction_id=transcation_id,
            transaction_status="PENDING"
        )

        """Update card balance"""
        card_instance.total_balance = card_instance.total_balance - amount
        card_instance.save()

        """Update user balance"""
        receiver_card_instance.total_balance = receiver_card_instance.total_balance + amount
        receiver_card_instance.save()

        """Update transcation status"""
        transcation_instance.transaction_status = "COMPLETED"
        transcation_instance.save()

        #Dear customer, your UPI transaction of Rs. 5,000 to 9876543210 has been successful. Thank you for using our banking services.
        try:
            txt_temp = f"Dear customer, your {APP_NAME_TEXT} transaction of Rs.{amount} to {user_instance.mobile} has been successful. Thank you for using our banking services."
            #PANGEA-REDACT
            redact_res = redact_text(txt_temp)
            if redact_res["status"] == "success":
                txt_temp = redact_res["body"]
                try:
                    # twilio_res = send_sms_to_mobile(txt_temp, user_instance.mobile)
                    twilio_res = "Need to add"
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)


        try:
            target_output=f"User-{user_instance.pid}",
            #PANGEA-IPGEOLOCATE
            ip_break = ip_geolocate(request.META.get('REMOTE_ADDR'))
            if ip_break["status"] == "success":
                # ip_break = ip_break["body"]
                target_output = f"{ip_break['body']['ip']} ({ip_break['body']['country_name']}) [{ip_break['body']['latitude']}|{ip_break['body']['longitude']}]"
            
            #PANGEA-AUDITLOG
            pangea_res = make_auditlog(
                message=f"Payment of {amount} is sent to {user_instance.name} from {user.name}",
                action="Payment Transfer",
                actor=f"User-{pid}",
                target=target_output,
                status="SUCCESS",
                source="Mobile Transfer"
            )     
        except Exception as e:
            print(e)


        """Add the money sent notification to the user and money received notification to the receiver"""
        try:
            #Money send notification to user
            user_notification = create_notification(
                pid=user.pid,
                title=f"₹ {amount} sent to {user_instance.name}",
                msg=f"₹ {amount} sent to {user_instance.name} successfully"    
            )
            print(f"User notification created {user_notification}")
            #Money received notification to receiver
            receiver_notification = create_notification(
                pid=to_pid,
                title=f"₹ {amount} received from {user.name}",
                msg=f"₹ {amount} received from {user.name} successfully"
            )
            print(f"Receiver notification created {receiver_notification}")
        except Exception as e:
            print(e)

        return display_response(
            msg="SUCCESS",
            err=None,
            body=None,
            statuscode=status.HTTP_200_OK
        )

class SetupPin(APIView):
    authentication_classes = [UserAuthentication]
    permission_classes = []

    def post(self, request, format=None):
        user=request.user
        pid = user.pid
        data = request.data

        old_pin = data.get("old_pin", None)
        new_pin = data.get("new_pin", None)

        if old_pin in ["", None] or new_pin in ["", None]:
            return display_response(
                msg="FAIL",
                err="Please provide user data",
                body=None,
                statuscode=status.HTTP_400_BAD_REQUEST
            )

        user_instance = UserModel.objects.filter(pid=pid).first()
        if user_instance is None:
            return display_response(
                msg="FAIL",
                err="User does not exist.Try signup",
                body=None,
                statuscode=status.HTTP_404_NOT_FOUND
            )

        #PANGEA_ENCRYPTION_PIN
        new_pin_encrypt = encrypt_vault(new_pin,ZPAY_PIN_VAULT)
        if new_pin_encrypt['status'] != "success":
            return display_response(
                msg="FAIL",
                err="Something went wrong in newpin encryption",
                body=None,
                statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        cipher_new_pin = new_pin_encrypt['body']['cipher_text']

        """If is_pin_set is True then old_pin is required"""
        msg_keyword = "set"
        if user_instance.is_pin_set:
            msg_keyword = "changed"
            """User Pin Checking"""
            old_pin_encrypt = encrypt_vault(old_pin,ZPAY_PIN_VAULT)
            if old_pin_encrypt['status'] != "success":
                return display_response(
                    msg="FAIL",
                    err="Something went wrong in ecryption",
                    body=None,
                    statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            cipher_old_pin = old_pin_encrypt['body']['cipher_text']


            if user_instance.pin != cipher_old_pin:
                return display_response(
                    msg="FAIL",
                    err="Pin is incorrect",
                    body=None,
                    statuscode=status.HTTP_406_NOT_ACCEPTABLE
                )
        if msg_keyword == "set":
            user_instance.is_pin_set = True

        user_instance.pin = cipher_new_pin
        user_instance.save()

        try:
            txt_temp = f"Dear customer, your {APP_NAME_TEXT} pin has been {msg_keyword} successful for the number {user_instance.mobile}. Thank you for using our banking services."
            #PANGEA-REDACT
            redact_res = redact_text(txt_temp)
            if redact_res["status"] == "success":
                txt_temp = redact_res["body"]
                try:
                    twilio_res = "Cheanged"
                    # twilio_res = send_sms_to_mobile(txt_temp, user_instance.mobile)
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)

        """Create notifications"""
        try:
            notify_res = create_notification(
                pid=pid,
                title=f"Transaction Pin {msg_keyword}",
                message=f"Your pin has been {msg_keyword} successfully",
            )
        except Exception as e:
            print(e)


        try:
            target_output=f"User-{user_instance.pid}",
            #PANGEA-IPGEOLOCATE
            ip_break = ip_geolocate(request.META.get('REMOTE_ADDR'))
            if ip_break["status"] == "success":
                # ip_break = ip_break["body"]
                target_output = f"{ip_break['body']['ip']} ({ip_break['body']['country_name']}) [{ip_break['body']['latitude']}|{ip_break['body']['longitude']}]"

            #PANGEA-LOG
            pangea_res = make_auditlog(
                message=f"Pin is set for {user_instance.name}",
                action="Pin Set",
                actor=None,
                target=target_output,
                status="SUCCESS",
                source="Mobile Pin Set"
            )     
        except Exception as e:
            print(e)



        return display_response(
            msg="SUCCESS",
            err=None,
            body=None,
            statuscode=status.HTTP_200_OK
        )

class UpdateCard(APIView):
    authentication_classes = [UserAuthentication]
    permission_classes = []

    def post(self,request):
        user=request.user
        pid = user.pid

        data = request.data
        card_number = data.get("card_number", None)

        if card_number in ["", None]:
            return display_response(
                msg="FAIL",
                err="Please provide card number",
                body=None,
                statuscode=status.HTTP_400_BAD_REQUEST
            )

        get_card = AddedCardsModel.objects.filter(card_number=card_number).first()
        if get_card is None:
            return display_response(
                msg="FAIL",
                err="Card does not exist",
                body=None,
                statuscode=status.HTTP_404_NOT_FOUND
            )

        get_card.is_active = not get_card.is_active
        get_card.save()

        return display_response(
            msg="SUCCESS",
            err=None,
            body={
                "is_active":get_card.is_active
            },
            statuscode=status.HTTP_200_OK
        )

class Notifications(APIView):
    authentication_classes = [UserAuthentication]
    permission_classes = []


    def convertdateformat(self, req_date):
        a = dtt.now(IST_TIMEZONE)
        currentdate = dtt(a.year,a.month,a.day,a.hour,a.minute,a.second)
        # datetime(year, month, day, hour, minute, second)
        x = dtt.strptime(req_date, YmdTHMSfz)
        notifcation_date = dtt(x.year, x.month, x.day, x.hour, x.minute, x.second)
        
        diff = currentdate - notifcation_date
        if diff.days <= 0:
            """return in 'x' hours ago format"""
            hrs = divmod(diff.seconds, 60) 
            if hrs[0] < 60 :
                return f"{hrs[0]} mins ago"
            else:
                x = divmod(hrs[0],60)
                return f"{x[0]} hrs ago"

        elif diff.days < 7:
            """return in 'x' days ago format"""
            return f"{diff.days} day ago"

        else:
            """return in 'x' created ago format"""
            return f"{diff.days} day ago"

    def get(self,request):
        user=request.user
        pid = user.pid

        json_data = {
            "notifications":[]
        }
        notifications = NotificationModel.objects.filter(pid=pid).order_by("-created_at")
        serializers = NotificationSerializer(notifications, many=True, context={"request":request})
        for i in serializers.data:
            i["created_at"] = self.convertdateformat(i["created_at"])
            json_data["notifications"].append({
                "id":i["id"],
                "title":i["title"],
                "message":i["message"],
                "created_at":i["created_at"]
            })
        
        return display_response(
            msg="SUCCESS",
            err=None,
            body=json_data,
            statuscode=status.HTTP_200_OK
        )

#------Search API's------
class SearchAPI(APIView):
    authentication_classes = [UserAuthentication]
    permission_classes = []

    def get(self, request, *args):
        user = request.user
        params = request.query_params
        search = params.get("query", None)

        # if search in ["", None]:
        #     return display_response(
        #         msg="FAIL",
        #         err="Please provide search query",
        #         body=None,
        #         statuscode=status.HTTP_400_BAD_REQUEST
        #     )
        
        json_data = {
            "users":[],
        }

        users = UserModel.objects.filter(Q(name__icontains=search) | Q(mobile__icontains=search) ) #.exclude(pid=user.pid)
        serializers = UserSerializer(users, many=True, context={"request":request})
        for i in serializers.data:
            #get the user card details
            card = AddedCardsModel.objects.filter(pid=i["pid"], is_verified=True).first()
            if card is not None:
                json_data["users"].append({
                    "pid":i["pid"],
                    "name":i["name"],
                    "mobile":i["mobile"],
                    "email":i["email"],
                    "img" : "https://img.freepik.com/free-psd/3d-illustration-person-with-sunglasses_23-2149436188.jpg",
                    "is_card_added":True
                })

        return display_response(
            msg="SUCCESS",
            err=None,
            body=json_data,
            statuscode=status.HTTP_200_OK
        )

#----QrScanChecker
class QrScanChecker(APIView):
    authentication_classes = [UserAuthentication]
    permission_classes = []

    def post(self,request):
        user = request.user
        data = request.data
        pid = data.get("pid", None)
        print("pid", pid)
        if pid in ["", None]:
            return display_response(
                msg="FAIL",
                err="QR code is not valid",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )
        
        get_user = UserModel.objects.filter(pid=pid).first()
        if get_user is None:
            return display_response(
                msg="FAIL",
                err="QR code is not valid",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )
    
        # if pid == user.pid:
        #     return display_response(
        #         msg="FAIL",
        #         err="You cannot scan your own QR code",
        #         body=None,
        #         statuscode=status.HTTP_406_NOT_ACCEPTABLE
        #     )

        return display_response(
            msg="SUCCESS",
            err=None,
            body={
                "pid":get_user.pid,
                "name":get_user.name,
                "mobile":get_user.mobile,
                "email":get_user.email,
            },
            statuscode=status.HTTP_200_OK
        )


class BreakdownResponse(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request, **kwargs):
        data = request.data
        #Get the IP address of the client
        print(request.META)
        print(request.META.get('REMOTE_ADDR'))
        return display_response(
            msg="SUCCESS",
            err=None,
            body=data,
            statuscode=status.HTTP_200_OK
        )
    
