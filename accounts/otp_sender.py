from django.conf import settings
from django.core.mail import send_mail


class EmailOTPSender:
    def __init__(self, otp:int, username:str):
        self.otp = otp
        self.username =  username

    def email_sender(self):
        subject = 'Sender message form ITS company'
        message = f'Hi. your OTP is {self.otp}, thank you for authorization'
        from_email  = settings.EMAIL_HOST_USER
        recipient_list = [self.username, ]
        send_mail(subject, message, from_email, recipient_list)


class PhoneOTPSender:
    def __init__(self, otp:int, phone:str):
        self.otp = otp
        self.phone = phone

    def phone_sender(self):
        pass