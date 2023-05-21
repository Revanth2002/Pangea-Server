from django.urls import path

from .views import *

urlpatterns = [
    path('login/', LoginUser.as_view(), name="login"), #added
    path('verify/', EnterLoginPin.as_view(), name="verify"), #added
    path('register/', RegisterUser.as_view(), name="register"), #added
    path("update-user/",UpdateUserInfo.as_view(),name="update-user"),
    path("add-card/",AddCard.as_view(),name="add-card"), #added
    path("get-cards/",GetCards.as_view(),name="get-cards"), #added
    path('update-cards/',UpdateCard.as_view(),name="update-cards"), #added
    path("myprofile/",MyProfile.as_view(),name="myprofile"), #pending qr code
    path("all-transactions/",AllTransactions.as_view(),name="all-transactions"), #added
    path("transaction-people/",PeopleTranscations.as_view(),name="transaction-details"), #added
    path("send-money/",SendPayment.as_view(),name="send-money"),
    path("home-screen/",HomeScreen.as_view(),name="home-screen"), #added
    path("setup-pin/",SetupPin.as_view(),name="setup-pin"), #added
    path("notification/",Notifications.as_view(),name="notification"), #added
    path('search/', SearchAPI.as_view(), name='search'), #added
    path("scan-qr/",QrScanChecker.as_view(),name="qr-code"), #added
    path('verify-card/', VerifyCard.as_view(), name='verify-card'), #added
    path('check-balance/',CheckBalance.as_view(), name='check-balance'), #added
    path('break/', BreakdownResponse.as_view(), name='break'),

]