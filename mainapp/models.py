from django.db import models

class UserModel(models.Model):
    pid = models.CharField(max_length=256, primary_key=True, unique=True)
    mobile = models.CharField(max_length=20, null=True, blank=True)
    email = models.CharField(max_length=50,null=True,blank=True)
    name = models.CharField(max_length=256,null=True,blank=True)
    password = models.CharField(max_length=255,null=True,blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    card_added = models.CharField(max_length=20, null=True, blank=True)
    is_pin_set = models.BooleanField(default=False)
    pin = models.CharField(max_length=512, null=True, blank=True)

    def __str__(self):
        return f"{self.pid}-{self.mobile}"
    
class UserOTPModel(models.Model):
    pid = models.CharField(max_length=40, null=True, blank=True)
    otp = models.CharField(max_length=20, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.pid}-{self.otp}"


class TransactionModel(models.Model):
    from_pid = models.CharField(max_length=256, null=True, blank=True)
    to_pid = models.CharField(max_length=256, null=True, blank=True)
    amount = models.FloatField(null=True, blank=True)
    card_id = models.CharField(max_length=256, null=True, blank=True)
    transaction_type = models.CharField(max_length=256, null=True, blank=True)
    transaction_id = models.CharField(max_length=256, null=True, blank=True)
    transaction_status = models.CharField(max_length=256, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.card_id}"

class AddedCardsModel(models.Model):
    pid = models.CharField(max_length=40, null=True, blank=True)
    card_number = models.CharField(max_length=20, null=True, blank=True)
    card_type = models.CharField(max_length=20, null=True, blank=True,default="debit")
    card_expiry = models.CharField(max_length=20, null=True, blank=True)
    card_cvv = models.CharField(max_length=20, null=True, blank=True)
    card_holder_name = models.CharField(max_length=256, null=True, blank=True)
    bank_name = models.CharField(max_length=256, null=True, blank=True,default="Axis")
    total_balance = models.FloatField(null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.pid} {self.card_number} {self.card_type} {self.card_expiry} {self.card_cvv} {self.card_holder_name} {self.bank_name}"
    

class NotificationModel(models.Model):
    pid = models.CharField(max_length=50, null=True, blank=True)
    title = models.CharField(max_length=255, null=True, blank=True)
    message = models.CharField(max_length=512, null=True, blank=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.pid} {self.title} {self.message} {self.is_read}"
    






