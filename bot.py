import os
import base64
import asyncio
from datetime import datetime, timezone
from urllib.parse import quote_plus

# --- Telegram Imports ---
from pyrogram import Client, filters
from pyrogram.types import Message

# --- Encryption Imports ---
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from hashids import Hashids

# --- Load Environment Variables ---
# Make sure to add ALL of these to Railway
API_ID = int(os.environ.get("API_ID", 0))
API_HASH = os.environ.get("API_HASH")
BOT_TOKEN = os.environ.get("BOT_TOKEN")
CRYPTO_KEY_B64 = os.environ.get("CRYPTO_KEY_B64")
HASH_SALT = os.environ.get("HASH_SALT")

# --- Setup Encryption ---
try:
    CRYPTO_KEY = base64.b64decode(CRYPTO_KEY_B64)
    hashids = Hashids(salt=HASH_SALT)
except Exception as e:
    print(f"Error loading keys: {e}. Make sure all environment variables are set.")
    CRYPTO_KEY = None
    hashids = None

# This is the domain of your website (from your app.py)
WEB_DOMAIN = "https.stream.anshbotzone.com"


# --- Missing Helper Functions ---
# These are the ENCRYPTION functions your bot needs.
# They are the reverse of the DECRYPTION functions in your helper.py

def encrypt_string(plain_text):
    """Encrypts text using AES CBC mode"""
    if not CRYPTO_KEY:
        raise ValueError("CRYPTO_KEY is not set")
    
    iv = get_random_bytes(16) # Generate a random IV
    cipher = AES.new(CRYPTO_KEY, AES.MODE_CBC, iv)
    
    # Pad the text and encrypt
    padded_data = pad(plain_text.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    # Return IV + Ciphertext, encoded in Base64
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def encode_string(plain_text):
    """Encodes text using Hashids (reverse of your decode_string)"""
    if not hashids:
        raise ValueError("HASH_SALT is not set")
        
    # Converts string to a list of character codes, then encodes
    return hashids.encode([ord(c) for c in plain_text])


# --- Setup Bot ---
if BOT_TOKEN:
    app = Client("my_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)
else:
    print("BOT_TOKEN is not set. Bot cannot start.")
    app = None

# --- Bot Handlers ---

@app.on_message(filters.command("start") & filters.private)
async def start_handler(client: Client, message: Message):
    """Handler for the /start command"""
    await message.reply_text(
        "Hi! I am your streaming link generator.\n\n"
        "Just send me any video file or forward it here, and I will give you a "
        "streaming link for your website."
    )

@app.on_message(filters.media & filters.private)
async def media_handler(client: Client, message: Message):
    """Handler for files (media)"""
    media = message.video or message.document
    
    if not media:
        await message.reply_text("Please send a video or document file.")
        return

    file_name = media.file_name or "Untitled"
    file_size = media.file_size or 0
    file_id = media.file_id # This is the 'url' for /tg/play
    
    # --- Create Metadata ---
    owner = message.from_user.first_name or "User"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %I:%M %p UTC")
    
    # Format: f_name|f_size|f_owner|f_time
    # This matches the format your app.py expects
    metadata_str = f"{file_name}|{file_size}|{owner}|{timestamp}"

    try:
        # --- Create Encrypted Links ---
        
        # 1. Encrypt the File ID for the 'url' parameter
        enc_file_id = encrypt_string(file_id)
        
        # 2. Encrypt the Metadata for the 'meta' parameter
        enc_metadata = encrypt_string(metadata_str)
        
        # 3. URL-encode the encrypted strings to make them safe for a URL
        safe_url = quote_plus(enc_file_id)
        safe_meta = quote_plus(enc_metadata)

        # 4. Build the final URL
        # This matches the /tg/play endpoint in your app.py
        final_link = f"{WEB_DOMAIN}/tg/play?url={safe_url}&meta={safe_meta}"
        
        await message.reply_text(
            f"**Your streaming link is ready!**\n\n"
            f"**File:** {file_name}\n"
            f"**Link:** `{final_link}`",
            disable_web_page_preview=True
        )

    except Exception as e:
        print(f"Error encrypting or sending link: {e}")
        await message.reply_text(
            "Sorry, something went wrong while generating the link. "
            "Please check the bot logs."
        )

# --- Start the Bot ---
async def main():
    if app:
        print("Bot is starting...")
        await app.start()
        print("Bot started successfully.")
        await asyncio.Event().wait() # Keep the bot running
    else:
        print("Bot could not be started.")

if __name__ == "__main__":
    asyncio.run(main())
