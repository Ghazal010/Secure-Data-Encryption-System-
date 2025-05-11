import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --- Fixed encryption key ---
KEY = b'M6ZSTcL__lFbmNzqg7NsTMT7VHoZgD-mY0Ot3dWz2SM='
cipher = Fernet(KEY)

# --- Set up session state for stored data ---
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

# --- Hashing function for passkey ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# --- Encryption ---
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# --- Decryption ---
def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# --- UI ---
st.title("Secure Data Encryption System 🔑")

menu = ["Home", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("Welcome to the Secure Data System 🔐")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter the data you want to store:")
    passkey = st.text_input("Enter a passkey to protect it:", type="password")
    
    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_pass = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)

            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_pass
            }

            st.success("✅ Your data has been encrypted and stored securely!")
            st.code(encrypted_text)
        else:
            st.error("⚠️ Please fill both the fields.")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Stored Data")
    encrypted_input = st.text_area("Enter your encrypted text:")
    passkey = st.text_input("Enter your passkey to decrypt:", type="password")

    if st.button("Retrieve"):
        if encrypted_input in st.session_state.stored_data:
            stored = st.session_state.stored_data[encrypted_input]
            if hash_passkey(passkey) == stored["passkey"]:
                try:
                    decrypted = decrypt_data(encrypted_input)
                    st.success("✅ Data Retrieved Successfully!")
                    st.code(decrypted)
                except Exception as e:
                    st.error("❌ Decryption failed. Invalid encrypted text.")
            else:
                st.error("❌ Incorrect passkey.")
        else:
            st.error("❌ Encrypted text not found in stored data.")
