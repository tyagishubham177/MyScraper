import os

# ——————————————————————————————————————————
# Config from GitHub Secrets / .env
URL       = ("https://shop.amul.com/en/product/"
             "amul-adrak-chai-instant-tea-mix-14-g-or-pack-of-10-sachets")
PINCODE   = os.getenv("PINCODE",  "110001")
# F2S_KEY   = os.getenv("F2S_API_KEY")             # Fast2SMS auth key
# F2S_TO    = os.getenv("F2S_NUMBERS")             # Comma-separated numbers (e.g. 91xxxxxxxxxx)
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_RECIPIENTS = os.getenv("EMAIL_RECIPIENTS")

# Base URL for the application itself, used for constructing absolute URLs if needed
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:3000")
# ——————————————————————————————————————————
