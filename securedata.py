import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac


DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60  


if "authentic_user" not in st.session_state:
    st.session_state.authentic_user = None
if "faild_attempts" not in st.session_state:
    st.session_state.faild_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

st.markdown("""
    <style>
        .stApp {
            background: url('https://www.shutterstock.com/image-photo/dangerous-anonymous-hacker-man-black-260nw-1660625353.jpg') no-repeat center center fixed;
            background-size: cover;
            color: white;
        }
        section[data-testid="stSidebar"] {
            background-color: #201f24 !important;
            color: white !important;
        }
        section[data-testid="stSidebar"] a,
        section[data-testid="stSidebar"] .css-1wvake5,
        section[data-testid="stSidebar"] .css-ewr35j {
            color: white !important;
        }
        h1, h2, h3, h4, h5, h6,
        label, .css-1cpxqw2 {
            color: white !important;
        }
        input, textarea {
            color: black !important;
        }
        .stButton > button {
            background-color: #16a085;
            color: white !important;
            font-weight: bold;
            border-radius: 10px;
            border: none;
            padding: 0.5rem 1rem;
            outline: none !important;
            box-shadow: none !important;
        }
        .stButton > button:hover {
            background-color: #0c97fa;
            color: white !important;
        }
        .stButton > button:focus,
        .stButton > button:active {
            color: white !important;
            outline: none !important;
            box-shadow: none !important;
        }
        div[data-testid^="stAlert"] {
            border-radius: 8px;
            padding: 12px;
            font-weight: bold;
            color: white !important;
        }
        div[data-testid="stAlert-success"] {
            background-color: #1e7e34 !important;
        }
        div[data-testid="stAlert-warning"] {
            background-color: #856404 !important;
        }
        div[data-testid="stAlert-error"] {
            background-color: #721c24 !important;
        }
        div[data-testid="stAlert-info"] {
            background-color: #0c5460 !important;
        }
    </style>
""", unsafe_allow_html=True)


def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# Utility Functions
def genreate_key(passkey):
    key = pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(genreate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(genreate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

store_data = load_data()


st.title("Welcome to the Secure Data App")

menu = ["🏠 Home", "📝 Register", "🔐 Login", "📥 Store Data", "📤 Retrieve Data"]
choice = st.sidebar.selectbox("📌 Navigation", menu)


if choice == "🏠 Home":
    st.subheader("Your data, your lock, your rules🔐")
    st.markdown("Protect your secrets with powerful encryption, unlocked only by you")

elif choice == "📝 Register":
    st.subheader("Create a New Account")
    username = st.text_input("Choose a User Name")
    password = st.text_input("Choose a Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in store_data:
                st.warning("⚠️ User already exists!")
            else:
                store_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(store_data)
                st.success("✅ Registration successful! You can now log in.")


elif choice == "🔐 Login":
    st.subheader("Login to Your Account")
    username = st.text_input("User Name")
    password = st.text_input("Password", type="password")
    current_time = time.time()

    if st.session_state.faild_attempts >= 3:
        time_left = int(st.session_state.lockout_time - current_time)
        if time_left > 0:
            timer = st.empty()
            st.warning("🚫 Too many failed attempts.")
            while time_left > 0:
                mins, secs = divmod(time_left, 60)
                timer.info(f"⏳ Please wait {mins:02d}:{secs:02d} before trying again...")
                time.sleep(1)
                time_left -= 1
                timer.empty()
            st.session_state.faild_attempts = 0
            st.session_state.lockout_time = 0
            st.rerun() 

    elif st.button("Login"):
        if username in store_data:
            stored_password = store_data[username]["password"]
            if hash_password(password) == stored_password:
                st.success("✅ Login successful!")
                st.session_state.authentic_user = username
                st.session_state.faild_attempts = 0
                st.session_state.lockout_time = 0
            else:
                st.error("❌ Incorrect password.")
                st.session_state.faild_attempts += 1
                if st.session_state.faild_attempts >= 3:
                    st.session_state.lockout_time = current_time + LOCKOUT_DURATION
        else:
            st.warning("⚠️ User not found.")

# Store Encrypted Data
elif choice == "📥 Store Data":
    if st.session_state.authentic_user:
        st.subheader("🔐 Store Your Secure Data")
        secret = st.text_area("Enter Data to Encrypt")
        key = st.text_input("Encryption Key", type="password")
        if st.button("Encrypt and Save"):
            encrypted = encrypt_text(secret, key)
            store_data[st.session_state.authentic_user]["data"].append(encrypted)
            save_data(store_data)
            st.success("✅ Data encrypted and saved.")
    else:
        st.warning("⚠️ Please login first.")

# Retrieve Data
elif choice == "📤 Retrieve Data":
    if st.session_state.authentic_user:
        st.subheader("🔓 Retrieve Your Encrypted Data")
        key = st.text_input("Enter your encryption key to decrypt", type="password")
        user_data = store_data[st.session_state.authentic_user]["data"]
        if user_data:
            for i, encrypted in enumerate(user_data):
                decrypted = decrypt_text(encrypted, key)
                st.text_area(f"Decrypted Data {i+1}", decrypted if decrypted else "Invalid key!", height=100)
        else:
            st.info("📭 No data stored yet.")
    else:
        st.warning("⚠️ Please login first.")
