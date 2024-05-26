from django.conf import settings
from django.core.mail import send_mail


class OTPSender:
    def __init__(self, otp:int):
        self.otp = otp
        self._phone = None
        self._email =  None

    @property
    def phone(self):
        return self._phone
    
    @phone.setter
    def phone(self, value):
        if not value:
            raise ValueError('phone cannot be empty')
        self._phone = value

    @property
    def email(self):
        return self._email
    
    @phone.setter
    def phone(self, value):
        if not value:
            raise ValueError('email cannot be empty')
        self._email = value

    def phone_sender(self):
        pass

    def email_sender(self):
        subject = 'Sender message form ITS company'
        message = f'Hi. your OTP is {self.otp}, thank you for authorization'
        email_from = settings.EMAIL_HOST_USER
        recipient_list = [self.email, ]
        send_mail( subject, message, email_from, recipient_list )