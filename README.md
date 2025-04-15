# Assignment05_secure_data_encryption
<pre> ```text +----------------------------+ | 🧾 User Input | | - Enters data & passkey | +-------------+-------------+ | v +----------------------------+ | 🔐 Encrypt & Hash | | - Fernet encrypts data | | - SHA-256 hashes passkey | +-------------+-------------+ | v +----------------------------+ | 💾 JSON Storage | | - Saves encrypted + hash | | - Format: {id: {enc, hash}}| +----------------------------+ -------- 🔄 Retrieval Process -------- +----------------------------+ | 🆔 Enter ID & Passkey | | - User enters both | +-------------+-------------+ | v +----------------------------+ | 🔍 Verify Passkey Hash | | - Hash user passkey | | - Compare with stored hash | +------+------+-------------+ | | Match? | | | Yes No | | v v +--------+ +--------------------------+ | 🔓 Show | | ⛔ Block after 3 attempts | | Decrypted| | - Login required after | | Data | | failure | +--------+ +--------------------------+ ``` </pre>
