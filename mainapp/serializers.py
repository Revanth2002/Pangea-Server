from rest_framework.serializers import ModelSerializer
from .models import *

class UserSerializer(ModelSerializer):
	class Meta:
		model=UserModel
		fields='__all__'

class TransactionSerializer(ModelSerializer):
	class Meta:
		model=TransactionModel
		fields='__all__'

class AddedCardSerializer(ModelSerializer):
	class Meta:
		model=AddedCardsModel
		fields='__all__'

class NotificationSerializer(ModelSerializer):
	class Meta:
		model=NotificationModel
		fields='__all__'