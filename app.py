import io
import os
import struct
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from PIL import Image
from cryptography.hazmat.primitives import hashes, padding as sympadding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import base64

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(16)  # for flash messages

# ---------- Crypto helpers ----------
def derive_key(password: bytes, salt: bytes, iterations: int = 200000) -> bytes:
    """Derive a 32-byte key from password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password)

def aes_encrypt(plaintext: bytes, password: str) -> bytes:
    """Encrypt plaintext using AES-256-CBC. Returns salt + iv + ciphertext (raw bytes)."""
    salt = secrets.token_bytes(16)
    key = derive_key(password.encode(), salt)
    iv = secrets.token_bytes(16)
    padder = sympadding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    # Prepend salt and iv to help decryption
    return salt + iv + ct

def aes_decrypt(blob: bytes, password: str) -> bytes:
    """Decrypt blob produced by aes_encrypt (salt + iv + ct)."""
    if len(blob) < 32:
        raise ValueError("Ciphertext too short.")
    salt = blob[:16]
    iv = blob[16:32]
    ct = blob[32:]
    key = derive_key(password.encode(), salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = sympadding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext

# ---------- LSB steganography helpers ----------
def _bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1

def _bits_to_bytes(bits):
    b = bytearray()
    byte = 0
    count = 0
    for bit in bits:
        byte = (byte << 1) | bit
        count += 1
        if count == 8:
            b.append(byte)
            byte = 0
            count = 0
    return bytes(b)

def embed_data_into_image(image: Image.Image, data: bytes) -> Image.Image:
    """
    Embeds data bytes into image LSBs.
    Data format: 4-byte length (unsigned int, big-endian) + payload bytes.
    """
    if image.mode not in ("RGB", "RGBA"):
        image = image.convert("RGBA")
    pixels = list(image.getdata())
    channels = 3  # use R,G,B channels only for embedding (skip alpha)
    total_pixels = len(pixels)
    total_capacity_bits = total_pixels * channels
    payload = struct.pack(">I", len(data)) + data  # 4-byte length prefix
    required_bits = len(payload) * 8
    if required_bits > total_capacity_bits:
        raise ValueError(f"Data too large to embed. Need {required_bits} bits; capacity is {total_capacity_bits} bits.")
    bit_iter = _bytes_to_bits(payload)
    new_pixels = []
    for pix in pixels:
        r, g, b, *rest = pix if len(pix) > 3 else (*pix, )
        r = (r & ~1) | next(bit_iter, 0)
        g = (g & ~1) | next(bit_iter, 0)
        b = (b & ~1) | next(bit_iter, 0)
        if len(pix) == 4:
            new_pixels.append((r, g, b, pix[3]))
        else:
            new_pixels.append((r, g, b))
        # Stop early if no bits left; remaining pixels can stay as-is (we already set LSB=0 if exhausted)
        if all(x is None for x in []) and False:
            pass
    # If bit_iter may still have bits (shouldn't), it's fine because we checked capacity
    out = Image.new(image.mode, image.size)
    out.putdata(new_pixels)
    return out

def extract_data_from_image(image: Image.Image) -> bytes:
    """
    Extracts data bytes from image LSBs.
    Assumes data stored as 4-byte length prefix followed by payload.
    """
    if image.mode not in ("RGB", "RGBA"):
        image = image.convert("RGBA")
    pixels = list(image.getdata())
    channels = 3
    bits = []
    for pix in pixels:
        r, g, b = pix[0], pix[1], pix[2]
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)
    # First 32 bits => length
    length_bits = bits[:32]
    length_bytes = _bits_to_bytes(length_bits)
    data_len = struct.unpack(">I", length_bytes)[0]
    total_data_bits = (4 + data_len) * 8
    if total_data_bits > len(bits):
        raise ValueError("Declared data length exceeds capacity or image truncated.")
    payload_bits = bits[32:32 + (data_len * 8)]
    payload = _bits_to_bytes(payload_bits)
    return payload

# ---------- Flask routes ----------
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/encode", methods=["POST"])
def encode():
    file = request.files.get("cover_image")
    message = request.form.get("message", "")
    password = request.form.get("password", "")
    if not file or not message or not password:
        flash("Please provide a cover image, message and password.")
        return redirect(url_for("index"))
    image = Image.open(file.stream).convert("RGBA")
    # Encrypt message
    encrypted = aes_encrypt(message.encode("utf-8"), password)  # bytes
    try:
        stego_img = embed_data_into_image(image, encrypted)
    except ValueError as e:
        flash(str(e))
        return redirect(url_for("index"))
    buf = io.BytesIO()
    stego_img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name="stego.png", mimetype="image/png")

@app.route("/decode", methods=["POST"])
def decode():
    file = request.files.get("stego_image")
    password = request.form.get("password", "")
    if not file or not password:
        flash("Please provide a stego image and password.")
        return redirect(url_for("index"))
    image = Image.open(file.stream).convert("RGBA")
    try:
        encrypted = extract_data_from_image(image)
    except Exception as e:
        flash(f"Extraction error: {e}")
        return redirect(url_for("index"))
    try:
        plaintext = aes_decrypt(encrypted, password)
    except Exception as e:
        flash("Decryption failed. Check password or image integrity.")
        return redirect(url_for("index"))
    return render_template("index.html", decoded_message=plaintext.decode("utf-8"))

if __name__ == "__main__":
    app.run(debug=True)
