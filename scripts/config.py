import os

# ——————————————————————————————————————————
# Config from GitHub Secrets / .env
URL = "https://shop.amul.com/en/product/amul-high-protein-rose-lassi-200-ml-or-pack-of-30"
PINCODE = os.getenv("PINCODE", "201305")
# F2S_KEY   = os.getenv("F2S_API_KEY")             # Fast2SMS auth key
# F2S_TO    = os.getenv("F2S_NUMBERS")             # Comma-separated numbers (e.g. 91xxxxxxxxxx)
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_RECIPIENTS = os.getenv("EMAIL_RECIPIENTS")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL") or os.getenv("ADMIN_MAIL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD") or os.getenv("ADMIN_PASSWORD_HASH")

# Allow a flexible window for scheduled job runs
RUN_OFFSET_MINUTES = 15

# Base URL for the application itself, used for constructing absolute URLs if needed
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:3000")
# Maximum number of product pages to check in parallel
MAX_PARALLEL_PAGE_CHECKS = int(os.getenv("MAX_PARALLEL_PAGE_CHECKS", "5"))
# ——————————————————————————————————————————
