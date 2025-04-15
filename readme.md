Assignment05_secure_data_encryption

+-----------------+
|   User Input    |
| (Data + Passkey)|
+--------+--------+
         |
         v
+------------------------+
| Encrypt & Hash (Python)|
| Fernet + SHA-256       |
+------------------------+
         |
         v
+-----------------+
|  JSON Storage   |
| {encrypted, hash}|
+-----------------+

--- When retrieving ---

+----------------------+
| User inputs ID & key |
+----------+-----------+
           |
           v
+---------------------------+
|  Hash key & compare hash  |
+-----------+---------------+
            |
   Match?   v
         [Yes] -----> Decrypt and show
         [No]  -----> Block after 3 tries
