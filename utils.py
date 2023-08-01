import base64
import pyotp
import pyqrcode
import io
import re
import secrets

# Function to generate a new CSRF token
def generate_csrf_token():
    return secrets.token_hex(16)

def is_password_complex(password):
    # Require at least 8 characters, with at least one uppercase letter, one lowercase letter, and one digit
    return bool(re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$', password))

def generate_qr_code(username, totp_secret):
    # Generate the TOTP URI using the username and TOTP secret
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username)

    # Generate the QR code using the TOTP URI
    qr_code = pyqrcode.create(totp_uri)

    # Save the QR code to a BytesIO buffer and return the image data as base64
    img_buffer = io.BytesIO()
    qr_code.png(img_buffer, scale=5)
    img_buffer.seek(0)
    qr_code_img = base64.b64encode(img_buffer.getvalue()).decode()

    return qr_code_img, totp_uri
