
# ZeroPay

ZeroPay is a digital payment platform which allows users to make payments, send money, and perform various financial transactions using their smartphones or other compatible devices. ZeroPay securely stores credit/debit card information, bank account details, and other payment methods via pangea api services, enabling users to make purchases online, in physical stores, and transfer money to other individuals. 

**Download APK** : ![apk](https://github.com/Revanth2002/Pangea-Server/releases/tag/v1.0)

## Highly Secured with Pangea Services

**Audit Log:** Logs every information of the event occuring during transactions and reports errors when occured.

**Redact:** Mobile number and Credit Cards are redacted to ensure high security.

**IP Intel:** Reputation and Geolocate are used to decode the IP address which used to find if it is malicious IP or not, thus increases the security of each api requests. 

**User Intel:** User Intel is used to check if the User’s Personally Identifiable Data or credentials such as email,card number is breached or not.If it is breached,then it is reported and audit is logged.

**Vault:** Asymmetric encryption is used to ensure that the transaction pin, credit cards and highly sensitive is secured via vault.

**AuthN:** Cloud-based authentication service that provides secure login, session management, and user management through hosted pages and APIs which meets the high security of authentication process.











## Deployment

  How to run django server and flutter app is given below

### Django Server 

Create a file with .env in the root directory and copy paste the contents of .env.txt into it. Change to your keys in this file

```bash
EMAIL_HOST_USER = '[Your-Email]'
EMAIL_HOST_PASSWORD = '[Your-Password]' 
DEFAULT_FROM_EMAIL='[Your-Email]'
PANGEA_API_KEY =  "[Your-Pangea-API-Key]"
PANGEA_DOMAIN = "[Your-Pangea-Domain]"
PANGEA_AUDIT_TOKEN =  "[Your-Pangea-Audit-Token]"
TWILIO_ACCOUNT_SID = "[Your-Twilio-Account-SID]"
TWILIO_AUTH_TOKEN = "[Your-Twilio-Auth-Token]"
CASHFREE_APPID="[Your-Cashfree-App-ID]"
CASHFREE_SECRET="[Your-Cashfree-Secret]"
```

Install python packages using the requirements.txt file

```bash
  pip install -r requirements.txt
```

To run the Django Server 
```bash
  python manage.py makemigrations
  python manage.py migrate
  python manage.py runserver 0.0.0.0
```

### Flutter 

Go to lib/helpers/routing.dart in your directory and change the DOMAIN to your network IP or Django Server IP
```bash
  const String DOMAIN = "[Your-IP-Here]"; 
```

To run the ZeroPay Mobile app via flutter
```bash
  flutter pub get
  futter run
```

## Test Credentials

Use the following test credentials to login/signup

```bash
  Mobile number : 9876543210
  OTP : 123456
  Email : <your-email>
```

