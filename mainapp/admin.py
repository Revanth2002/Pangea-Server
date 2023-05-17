from django.contrib import admin
from .models import *

admin.site.register(UserModel)
admin.site.register(TransactionModel)
admin.site.register(AddedCardsModel)
admin.site.register(UserOTPModel)
admin.site.register(NotificationModel)