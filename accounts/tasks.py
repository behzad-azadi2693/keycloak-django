from celery import shared_task
from utils import OTPSender


@shared_task
def otp_email_sender(otp, email):
    sender = OTPSender(otp)
    sender.email = email
    sender.email_sender()


@shared_task
def otp_phone_sender(otp, phone):
    sender = OTPSender(otp)
    sender.email = phone
    sender.phone_sender()