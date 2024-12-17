from celery import shared_task
from .otp_sender import EmailOTPSender, PhoneOTPSender


@shared_task(bind=True)
def otp_email_sender(self, otp:int, email:str):
    email_send = EmailOTPSender(otp, email)
    email_send.email_sender()


@shared_task(bind=True)
def otp_phone_sender(self, otp, phone):
    phone_send = PhoneOTPSender(otp, phone)
    phone_send.phone_sender()
