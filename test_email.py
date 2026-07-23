import os
from dotenv import load_dotenv
import smtplib
from email.message import EmailMessage

load_dotenv()

server = os.getenv("SMTP_SERVER")
port = int(os.getenv("SMTP_PORT", "587"))
username = os.getenv("SMTP_USERNAME")
password = os.getenv("SMTP_PASSWORD")
from_email = os.getenv("EMAIL_FROM")

try:
    msg = EmailMessage()
    msg.set_content("Test OTP: 123456")
    msg['Subject'] = "CryptoDetect Test OTP"
    msg['From'] = from_email
    msg['To'] = username

    print(f"Connecting to {server}:{port}...")
    with smtplib.SMTP(server, port) as smtp:
        smtp.starttls()
        smtp.login(username, password)
        smtp.send_message(msg)
    print("Success! Email sent.")
except Exception as e:
    print(f"Error: {e}")
