from config.celery import APP
from utils import OTPSender


@APP.task()
def otp_email_sender(otp, email):
    sender = OTPSender(otp)
    sender.email = email
    sender.email_sender()


@APP.task()
def otp_phone_sender(otp, phone):
    sender = OTPSender(otp)
    sender.email = phone
    sender.phone_sender()