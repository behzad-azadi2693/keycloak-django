from celery import shared_task
from utils import OTPSender


@shared_task(bind=True)
def otp_email_sender(self, otp: int, email: str):
    sender = OTPSender(otp)
    sender.email = email
    sender.email_sender()


@shared_task(bind=True)
def otp_phone_sender(self, otp, phone):
    sender = OTPSender(otp)
    sender.email = phone
    sender.phone_sender()
