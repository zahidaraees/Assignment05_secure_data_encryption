"""
Assignment 5 as per Sir Arif
Assignment 6 as per class. 
Secure Data Encryption Application with streamlit

"""
import streamlit as st
from cryptography.fernet import Fernet
import hashlib

# Global in-memory store
stored_data = {}

# Encryption key for the whole app (fixed key for assignment)
fernet_key = Fernet.generate_key()
cipher = Fernet(fernet_key)

# Master password for login
MASTER_PASSWORD = "admin123"

# Initialize session state
if 'page' not in st.session_state:
    st.session_state.page = "Home"
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = True

# Helper functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(data, passkey):
    hashed_pass = hash_passkey(passkey)
    encrypted = cipher.encrypt(data.encode())
    return encrypted.decode(), hashed_pass

def decrypt_data(encrypted_text, passkey, stored_hash):
    if hash_passkey(passkey) == stored_hash:
        decrypted = cipher.decrypt(encrypted_text.encode()).decode()
        st.session_state.failed_attempts = 0
        return decrypted
    else:
        st.session_state.failed_attempts += 1
        return None

# Navigation
st.sidebar.title("🔐 Navigation")
pages = ["Home", "Store Data", "Retrieve Data", "Login"]
selected = st.sidebar.selectbox("Go to", pages)

if st.session_state.failed_attempts >= 3:
    st.session_state.logged_in = False
    st.session_state.page = "Login"
else:
    st.session_state.page = selected

# Pages
if st.session_state.page == "Home":
    st.title("🔒 Secure Data Encryption")
    st.write("Store and retrieve encrypted data using a secure passkey.")
    st.write("Data is stored in memory and encrypted with Fernet encryption.")

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
            st.success("✅ Data stored successfully!")
            st.code(data_id, language="text")
        else:
            st.error("❗ Please enter both data and a passkey.")

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
                st.code(decrypted, language="text")
            else:
                st.error("❌ Incorrect passkey.")
        else:
            st.error("❌ Data ID not found.")
    st.warning(f"Attempts remaining: {3 - st.session_state.failed_attempts}")

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
            else:
                st.error("❌ Incorrect password.")

# Footer
st.markdown("---")
st.caption("Project by Zahida Raees | Assignment 5")
