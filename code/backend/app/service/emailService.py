"""
Email service for sending OTP codes and notifications.
"""

from email.message import EmailMessage

import aiosmtplib
from decouple import config

SMTP_HOST = config("SMTP_HOST")
SMTP_PORT = config("SMTP_PORT", cast=int)
SMTP_USER = config("SMTP_USER")
SMTP_PASSWORD = config("SMTP_PASSWORD")
EMAIL_FROM = config("EMAIL_FROM")


async def send_otp_email(to_email: str, otp_code: str) -> None:
    """
    Envoie un code OTP par email.
    """
    msg = EmailMessage()
    msg["From"] = EMAIL_FROM
    msg["To"] = to_email
    msg["Subject"] = "Code de verification"
    msg.set_content(
        f"Votre code de verification est: {otp_code} \n"
        f"Ce code est valide pour 5 minutes.\n\n"
        f"Si vous n'avez pas demande ce code, veuillez ignorer cet email."
    )

    await aiosmtplib.send(
        msg,
        hostname=SMTP_HOST,
        port=SMTP_PORT,
        username=SMTP_USER,
        password=SMTP_PASSWORD,
        start_tls=True,
    )
