# -*- coding: utf-8 -*-
import streamlit as st
import hashlib
import jwt
import csv
import os
import time
import pandas as pd
import struct
from tinyec import registry
from Crypto.Hash import SHA3_256
import psutil  # For memory measurement
import timeit  # For precise timing

# ==========================================
# 1. LEAIoT Key Management
# ==========================================
class LEAIoT:
    def __init__(self):
        self.master_key = os.urandom(10)  # 80-bit key for PRESENT
        self.last_rotation = time.time()
        self.rotation_interval = 3600  # seconds

    def rotate_keys(self):
        if time.time() - self.last_rotation > self.rotation_interval:
            self.master_key = os.urandom(10)
            self.last_rotation = time.time()
            st.write("[LEAIoT] Key Rotated.")

    def get_key(self):
        return self.master_key

# ==========================================
# 2. ECC Key Exchange
# ==========================================
class ECCKeyExchange:
    def __init__(self):
        self.curve = registry.get_curve('brainpoolP256r1')
        self.private_key = os.urandom(32)
        self.private_int = int.from_bytes(self.private_key, 'big')
        self.public_key = self.private_int * self.curve.g

    def get_shared_key(self, other_pub):
        shared_point = self.private_int * other_pub
        return SHA3_256.new(int(shared_point.x).to_bytes(32, 'big')).digest()[:10]  # 80-bit

# ==========================================
# 3. Full PRESENT Cipher (80-bit Key, 64-bit Block, 31 Rounds)
# ==========================================
SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
        0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]

PBOX = [0, 16, 32, 48, 1, 17, 33, 49,
        2, 18, 34, 50, 3, 19, 35, 51,
        4, 20, 36, 52, 5, 21, 37, 53,
        6, 22, 38, 54, 7, 23, 39, 55,
        8, 24, 40, 56, 9, 25, 41, 57,
        10, 26, 42, 58, 11, 27, 43, 59,
        12, 28, 44, 60, 13, 29, 45, 61,
        14, 30, 46, 62, 15, 31, 47, 63]

def sbox_layer64(state):
    return sum([SBOX[(state >> (4*i)) & 0xF] << (4*i) for i in range(16)])

def pbox_layer64(state):
    out = 0
    for i in range(64):
        bit = (state >> i) & 1
        out |= bit << PBOX[i]
    return out

def generate_round_keys(master_key):
    round_keys = []
    key = int.from_bytes(master_key, 'big')
    for i in range(32):
        round_keys.append((key >> 16) & 0xFFFFFFFFFFFFFFFF)
        # 61-bit left rotate
        key = ((key << 61) | (key >> 19)) & ((1 << 80) - 1)
        # S-box on MSbits
        sbox_input = (key >> 76) & 0xF
        key &= ~(0xF << 76)
        key |= SBOX[sbox_input] << 76
        # XOR round counter
        key ^= i << 15
    return round_keys

def present_encrypt(block, key):
    assert len(block) == 8 and len(key) == 10
    state = int.from_bytes(block, 'big')
    round_keys = generate_round_keys(key)
    for i in range(31):
        state ^= round_keys[i]
        state = sbox_layer64(state)
        state = pbox_layer64(state)
    state ^= round_keys[31]
    return state.to_bytes(8, 'big')

def present_decrypt(block, key):
    assert len(block) == 8 and len(key) == 10
    state = int.from_bytes(block, 'big')
    round_keys = generate_round_keys(key)
    state ^= round_keys[31]
    for i in reversed(range(31)):
        # Inverse P-layer
        tmp = 0
        for j in range(64):
            bit = (state >> PBOX[j]) & 1
            tmp |= bit << j
        state = tmp
        # Inverse S-box layer
        state = sum([SBOX.index((state >> (4*k)) & 0xF) << (4*k) for k in range(16)])
        state ^= round_keys[i]
    return state.to_bytes(8, 'big')

# ==========================================
# 4. Full ASCON-128 AEAD
# ==========================================
def rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF

def ascon_permutation(s, rounds=12):
    ROUND_CONSTANTS = [
        0x0f0e0d0c0b0a0908, 0x0706050403020100,
        0x1716151413121110, 0x1f1e1d1c1b1a1918,
        0x2726252423222120, 0x2f2e2d2c2b2a2928,
        0x3736353433323130, 0x3f3e3d3c3b3a3938,
        0x4746454443424140, 0x4f4e4d4c4b4a4948,
        0x5756555453525150, 0x5f5e5d5c5b5a5958,
    ][12 - rounds:]

    for rc in ROUND_CONSTANTS:
        s[2] ^= rc
        x0, x1, x2, x3, x4 = s
        x0 ^= x4
        x4 ^= x3
        x2 ^= x1

        t0 = (~x0) & x1
        t1 = (~x1) & x2
        t2 = (~x2) & x3
        t3 = (~x3) & x4
        t4 = (~x4) & x0

        x0 ^= t1
        x1 ^= t2
        x2 ^= t3
        x3 ^= t4
        x4 ^= t0

        x1 ^= x0
        x0 ^= x4
        x3 ^= x2
        x2 = ~x2 & 0xFFFFFFFFFFFFFFFF

        s[0] = x0 ^ rotr(x0, 19) ^ rotr(x0, 28)
        s[1] = x1 ^ rotr(x1, 61) ^ rotr(x1, 39)
        s[2] = x2 ^ rotr(x2, 1) ^ rotr(x2, 6)
        s[3] = x3 ^ rotr(x3, 10) ^ rotr(x3, 17)
        s[4] = x4 ^ rotr(x4, 7) ^ rotr(x4, 41)
    return s

class Ascon128:
    def __init__(self, key: bytes, nonce: bytes):
        assert len(key) == 16 and len(nonce) == 16
        self.key = key
        self.nonce = nonce

    def initialize(self):
        IV = 0x80400c0600000000  # ASCON-128 IV
        K0, K1 = struct.unpack(">QQ", self.key)
        N0, N1 = struct.unpack(">QQ", self.nonce)
        state = [IV, K0, K1, N0, N1]
        return ascon_permutation(state, rounds=12)

    def encrypt(self, plaintext: bytes):
        state = self.initialize()
        # Absorb plaintext (only one block here for simplicity)
        pt_block = int.from_bytes(plaintext.ljust(8, b'\x00'), 'big')
        state[0] ^= pt_block
        ct_block = state[0]
        state = ascon_permutation(state, rounds=12)
        # Finalization
        K0, K1 = struct.unpack(">QQ", self.key)
        state[3] ^= K0
        state[4] ^= K1
        state = ascon_permutation(state, rounds=12)
        state[3] ^= K0
        state[4] ^= K1
        tag = struct.pack(">QQ", state[3], state[4])
        ciphertext = ct_block.to_bytes(8, 'big')
        return ciphertext, tag[:16]

    def decrypt(self, ciphertext: bytes, tag: bytes):
        state = self.initialize()
        ct_block = int.from_bytes(ciphertext, 'big')
        pt_block = state[0] ^ ct_block
        state[0] = ct_block
        state = ascon_permutation(state, rounds=12)
        # Finalization
        K0, K1 = struct.unpack(">QQ", self.key)
        state[3] ^= K0
        state[4] ^= K1
        state = ascon_permutation(state, rounds=12)
        state[3] ^= K0
        state[4] ^= K1
        expected_tag = struct.pack(">QQ", state[3], state[4])[:16]
        if expected_tag != tag:
            raise ValueError("MAC check failed!")
        return pt_block.to_bytes(8, 'big')

# ==========================================
# 5. CP-ABE
# ==========================================
class CPABE:
    def __init__(self, policy: str):
        self.policy = policy  # e.g., 'role:doctor AND department:cardiology'

    def encrypt(self, ciphertext: bytes, mac: bytes):
        return {
            "policy": self.policy,
            "data": ciphertext,
            "mac": mac
        }

    def decrypt(self, enc_package: dict, user_attributes: dict):
        required = [x.strip() for x in enc_package['policy'].split('AND')]
        for condition in required:
            k, v = condition.split(':')
            if user_attributes.get(k.strip()) != v.strip():
                raise PermissionError(f"Access Denied. Missing attribute: {k.strip()}={v.strip()}")
        return enc_package['data'], enc_package['mac']

# ==========================================
# 6. JWT tokens + SHA
# ==========================================

SECRET_KEY = "my_super_secret_key"  # Keep this safe in production!

def sha256_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_jwt(payload):
    return jwt.encode(
        {"data": payload, "exp": time.time() + 3600},  # token expires in 1 hour
        SECRET_KEY,
        algorithm="HS256"
    )

def decode_jwt(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded["data"]
    except jwt.ExpiredSignatureError:
        st.error("Session expired. Please login again.")
        return None
    except jwt.InvalidTokenError:
        st.error("Invalid token.")
        return None

# ==========================================
# 7. Authentication Function
# ==========================================
def authenticate_user():
    # Hardcoded users with SHA-256 hashed passwords
    users = {
        "alice": {
            "password": sha256_hash("alice123"),
            "role": "doctor",
            "department": "cardiology"
        },
        "bob": {
            "password": sha256_hash("bob123"),
            "role": "doctor",
            "department": "pulmonology"
        },
        "carol": {
            "password": sha256_hash("carol123"),
            "role": "doctor",
            "department": "neurology"
        },
        "dave": {
            "password": sha256_hash("dave123"),
            "role": "nurse",
            "department": "cardiology"
        },
    }

    with st.form("login_form"):
        st.subheader("Medical Data Access Portal")
        username = st.text_input("Username").strip().lower()
        password = st.text_input("Password", type="password").strip()
        submitted = st.form_submit_button("Login")
        
        if submitted:
            hashed_input = sha256_hash(password)
            
            if username in users and users[username]["password"] == hashed_input:
                role = users[username]["role"]
                dept = users[username]["department"]
                st.success(f"Authentication successful. Welcome, {username.capitalize()}!")
                
                token = generate_jwt({"username": username, "role": role, "department": dept})
                st.session_state['token'] = token
                st.session_state['authenticated'] = True
                st.session_state['user_data'] = {"username": username, "role": role, "department": dept}
                st.rerun() 
            else:
                st.error("Authentication failed. Invalid username or password.")

# ==========================================
# 8. Performance Measurement Utilities
# ==========================================
def get_memory_usage():
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)  # Return in MB

def measure_time(func, *args, **kwargs):
    start_time = timeit.default_timer()
    result = func(*args, **kwargs)
    elapsed = timeit.default_timer() - start_time
    return result, elapsed

# ==========================================
# 9. Main Application with Performance Tracking
# ==========================================
def secure_demo_pipeline():
    # === Load Data ===
    try:
        signals = pd.read_csv("signals.csv")
        numerics = pd.read_csv("numerics.csv")
        breath = pd.read_csv("breath.csv")
    except FileNotFoundError:
        st.error("Required data files not found. Please ensure signals.csv, numerics.csv, and breath.csv are in the same directory.")
        return

    # === Select Sample Fields ===
    signal_col = next((col for col in signals.columns if 'PLETH' in col.upper()), signals.columns[0])
    numeric_col = next((col for col in numerics.columns if numerics[col].dtype in ['int64', 'float64']), numerics.columns[0])
    breath_col = next((col for col in breath.columns if breath[breath[col].notnull()].shape[0] > 0), breath.columns[0])

    # Prepare samples
    signal_sample = str(signals.iloc[0][signal_col])[:8].ljust(8, '0').encode()
    numeric_sample = str(numerics.iloc[0][numeric_col])[:8].ljust(8, '0').encode()
    breath_sample = str(breath.iloc[0][breath_col])[:8].ljust(8, '0').encode()

    samples = {
        "signals": signal_sample,
        "numerics": numeric_sample,
        "breath": breath_sample
    }

    dataframes = {
        "signals": signals,
        "numerics": numerics,
        "breath": breath
    }

    # === Key Exchange & Session Key ===
    leaiot = LEAIoT()
    ecc_server = ECCKeyExchange()
    ecc_device = ECCKeyExchange()
    session_key = ecc_server.get_shared_key(ecc_device.public_key)

    # === ASCON Setup ===
    ascon_key = os.urandom(16)
    ascon_nonce = os.urandom(16)
    ascon = Ascon128(key=ascon_key, nonce=ascon_nonce)

    # Get user data from session
    user_data = st.session_state.get('user_data')
    if user_data is None:
        st.error("User data not found. Please login again.")
        return

    user_role = user_data["role"]
    user_department = user_data["department"]
    user_attrs = {"role": user_role, "department": user_department}

    # === Permission Logic ===
    access_map = {
        "signals": {"role": "doctor", "department": "cardiology"},
        "breath": {"role": "doctor", "department": "pulmonology"},
        "numerics": {"role": "doctor", "department": "neurology"},
    }

    if user_role != "doctor":
        st.warning("Access Denied: Nurses are not allowed to access any files.")
        return

    st.subheader("Medical Data Access")
    st.write(f"Logged in as: {user_role.capitalize()} from {user_department.capitalize()} department")

    # Performance metrics storage
    performance_data = {
        "Operation": [],
        "Encryption Time (ms)": [],
        "Decryption Time (ms)": [],
        "Memory Usage (MB)": []
    }

    for label, data in samples.items():
        required = access_map[label]
        if user_attrs['role'] == required['role'] and user_attrs['department'] == required['department']:
            with st.expander(f"{label.upper()} Data"):
                # Measure memory before operations
                mem_before = get_memory_usage()

                # Encrypt using PRESENT with timing
                present_start = timeit.default_timer()
                enc_present = present_encrypt(data, session_key)
                present_time = (timeit.default_timer() - present_start) * 1000  # ms

                # Encrypt using ASCON with timing
                ascon_start = timeit.default_timer()
                ciphertext, mac = ascon.encrypt(enc_present)
                ascon_time = (timeit.default_timer() - ascon_start) * 1000  # ms

                # Wrap using CP-ABE
                cpabe = CPABE(policy=f"role:{required['role']} AND department:{required['department']}")
                encrypted_package = cpabe.encrypt(ciphertext, mac)

                # Try decrypting using user attributes with timing
                try:
                    # Measure decryption time
                    dec_start = timeit.default_timer()
                    ct_from_cpabe, mac_from_cpabe = cpabe.decrypt(encrypted_package, user_attrs)
                    decrypted = ascon.decrypt(ct_from_cpabe, mac_from_cpabe)
                    final_data = present_decrypt(decrypted, session_key)
                    dec_time = (timeit.default_timer() - dec_start) * 1000  # ms

                    # Measure memory after operations
                    mem_after = get_memory_usage()

                    # Store performance data
                    performance_data["Operation"].append(label)
                    performance_data["Encryption Time (ms)"].append(present_time + ascon_time)
                    performance_data["Decryption Time (ms)"].append(dec_time)
                    performance_data["Memory Usage (MB)"].append(mem_after - mem_before)

                    # Display data
                    df = dataframes[label]
                    st.dataframe(df.head(100))
                except PermissionError as e:
                    st.error(str(e))

    # Display performance metrics in a table
    if performance_data["Operation"]:
        st.subheader("Performance Metrics")
        perf_df = pd.DataFrame(performance_data)
        st.table(perf_df)

        # Display summary statistics
        st.subheader("Summary Statistics")
        col1, col2, col3 = st.columns(3)
        
        avg_enc_time = perf_df["Encryption Time (ms)"].mean()
        avg_dec_time = perf_df["Decryption Time (ms)"].mean()
        avg_mem = perf_df["Memory Usage (MB)"].mean()
        
        col1.metric("Avg Encryption Time", f"{avg_enc_time:.2f} ms")
        col2.metric("Avg Decryption Time", f"{avg_dec_time:.2f} ms")
        col3.metric("Avg Memory Usage", f"{avg_mem:.2f} MB")

# Main app
def main():
    st.set_page_config(page_title="Secure Medical Data Portal", layout="wide")
    
    if 'authenticated' not in st.session_state:
        st.session_state['authenticated'] = False
    
    if not st.session_state['authenticated']:
        authenticate_user()
    else:
        secure_demo_pipeline()
        if st.button("Logout"):
            st.session_state.clear()
            st.rerun()

if __name__ == "__main__":
    main()