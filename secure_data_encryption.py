"""
Assignment 5 as per Sir Arif
Assignment 6 as per class. 
Secure Data Encryption Application with streamlit

"""
import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import json
import os

# === CONFIG ===
MASTER_PASSWORD = "admin123"
DATA_FILE = "data_store.json"
fernet_key = Fernet.generate_key()
cipher = Fernet(fernet_key)

# === DATA HANDLING ===
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

stored_data = load_data()

# === HASHING & ENCRYPTION ===
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(data, passkey):
    hashed = hash_passkey(passkey)
    encrypted = cipher.encrypt(data.encode())
    return encrypted.decode(), hashed

def decrypt_data(encrypted_text, passkey, stored_hash):
    if hash_passkey(passkey) == stored_hash:
        decrypted = cipher.decrypt(encrypted_text.encode()).decode()
        st.session_state.failed_attempts = 0
        return decrypted
    else:
        st.session_state.failed_attempts += 1
        return None

# === SESSION STATE INIT ===
if 'page' not in st.session_state:
    st.session_state.page = "Home"
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = True

# === NAVIGATION ===
st.sidebar.title("🔐 Navigation")
pages = ["Home", "Store Data", "Retrieve Data", "Login"]
selected = st.sidebar.selectbox("Go to", pages)

# Lock user out after 3 failed attempts
if st.session_state.failed_attempts >= 3:
    st.session_state.logged_in = False
    st.session_state.page = "Login"
else:
    st.session_state.page = selected

# === HOME PAGE ===
if st.session_state.page == "Home":
    st.title("🔒 Secure Data Encryption")
    st.write("Use this app to **securely store and retrieve data** using encryption.")
    
    st.markdown("### 📄 Stored Data IDs:")
    if stored_data:
        for data_id in stored_data:
            with st.expander(f"🗂️ {data_id}"):
                st.text("Encrypted text (truncated):")
                st.code(stored_data[data_id]['encrypted'][:50] + "...")

                # Delete option
                if st.button(f"❌ Delete {data_id}", key=data_id):
                    del stored_data[data_id]
                    save_data(stored_data)
                    st.success(f"{data_id} deleted successfully.")
                    st.experimental_rerun()
    else:
        st.info("No data stored yet.")

# === STORE DATA PAGE ===
elif st.session_state.page == "Store Data":
    st.title("📦 Store Encrypted Data")
    data = st.text_area("Enter the data you want to encrypt:")
    passkey = st.text_input("Enter a passkey", type="password")

    if st.button("Encrypt & Store"):
        if data and passkey:
            encrypted, hashed = encrypt_data(data, passkey)
            data_id = f"data_{len(stored_data)+1}"
            stored_data[data_id] = {
                "encrypted": encrypted,
                "passkey": hashed
            }
            save_data(stored_data)
            st.success("✅ Data stored successfully!")
            st.code(data_id, language="text")
        else:
            st.error("❗ Please enter both data and a passkey.")

# === RETRIEVE DATA PAGE ===
elif st.session_state.page == "Retrieve Data":
    st.title("🔓 Retrieve Encrypted Data")
    data_id = st.text_input("Enter Data ID")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("Decrypt"):
        if data_id in stored_data:
            record = stored_data[data_id]
            decrypted = decrypt_data(record["encrypted"], passkey, record["passkey"])
            if decrypted:
                st.success("✅ Decryption Successful!")
                st.markdown("### 🔍 Decrypted Data:")
                st.code(decrypted, language="text")
            else:
                st.error("❌ Incorrect passkey.")
        else:
            st.error("❌ Data ID not found.")
    st.warning(f"Attempts remaining: {3 - st.session_state.failed_attempts}")

# === LOGIN PAGE ===
elif st.session_state.page == "Login":
    st.title("🔑 Login Required")
    if st.session_state.logged_in:
        st.success("✅ Already logged in.")
    else:
        password = st.text_input("Enter master password", type="password")
        if st.button("Login"):
            if password == MASTER_PASSWORD:
                st.success("✅ Login successful.")
                st.session_state.failed_attempts = 0
                st.session_state.logged_in = True
                st.session_state.page = "Home"
                st.experimental_rerun()
            else:
                st.error("❌ Incorrect password.")

# === FOOTER ===
st.markdown("---")
st.caption("🔐 Secure Data Encryption App | Assignment 05 – by Zahida Raees")
