import os
import time
import socket
import tempfile
import threading

import config
import crypto_utils
import network_utils
import auth

def run_test():
    print("==================================================")
    print("      RUNNING INTEGRATION & CRYPTO TESTS         ")
    print("==================================================")

    # 1. Test Keypair & Crypto
    priv, pub = crypto_utils.generate_rsa_keypair(2048)
    aes_key = crypto_utils.generate_aes_key()
    nonce = crypto_utils.generate_gcm_nonce()

    enc_aes_key = crypto_utils.encrypt_aes_key_rsa(pub, aes_key)
    dec_aes_key = crypto_utils.decrypt_aes_key_rsa(priv, enc_aes_key)
    assert aes_key == dec_aes_key, "RSA key exchange failed"
    print("[PASS] RSA-2048 OAEP AES Session Key Encryption & Decryption")

    # 2. Test AES-GCM Streaming Cipher
    test_data = b"Hello, Secure WLAN File Sharing World! " * 1000
    enc = crypto_utils.StreamingAESGCMEncryptor(aes_key, nonce)
    c1 = enc.update(test_data)
    c2, tag = enc.finalize()
    ciphertext = c1 + c2

    dec = crypto_utils.StreamingAESGCMDecryptor(aes_key, nonce, tag)
    d1 = dec.update(ciphertext)
    d2 = dec.finalize()
    decrypted_data = d1 + d2
    assert test_data == decrypted_data, "AES-GCM streaming decryption mismatch"
    print("[PASS] AES-256-GCM Streaming Cipher & Tag Validation")

    # 3. Test SHA-256 Digest
    hash1 = crypto_utils.calculate_bytes_sha256(test_data)
    hash2 = crypto_utils.calculate_bytes_sha256(decrypted_data)
    assert hash1 == hash2, "SHA-256 hash digest mismatch"
    print("[PASS] SHA-256 File Integrity Check")

    # 4. Test Authentication Hashing
    salt, pwd_hash = auth.hash_password("mysecretpassword")
    assert auth.verify_password(salt, pwd_hash, "mysecretpassword") is True
    assert auth.verify_password(salt, pwd_hash, "wrongpassword") is False
    print("[PASS] PBKDF2-HMAC-SHA256 Password Authentication")

    # 5. Socket Server / Client Automated Transfer Test
    print("\n--- Running Socket Server/Client E2E Transfer Test ---")
    test_port = 5555
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", test_port))
    server_sock.listen(1)

    # Create dummy source file
    sample_file_path = config.BASE_DIR / "test_sample.txt"
    with open(sample_file_path, "wb") as f:
        f.write(b"ACADEMIC PROJECT DEMO FILE - SECURE TRANSMISSION\n" * 500)

    server_received_success = False

    def receiver_worker():
        nonlocal server_received_success
        conn, addr = server_sock.accept()
        
        # Auth
        auth_msg = network_utils.recv_json_message(conn)
        assert auth_msg["action"] == "AUTH"
        assert auth.authenticate_user(auth_msg["username"], auth_msg["password"])
        network_utils.send_json_message(conn, {"status": "AUTH_OK", "public_key": pub.decode('utf-8')})

        # Metadata
        meta_msg = network_utils.recv_json_message(conn)
        assert meta_msg["action"] == "TRANSFER"
        enc_filesize = meta_msg["enc_filesize"]
        encrypted_aes_key = bytes.fromhex(meta_msg["encrypted_aes_key"])
        nonce_val = bytes.fromhex(meta_msg["nonce"])
        tag_val = bytes.fromhex(meta_msg["tag"])
        expected_sha = meta_msg["sha256"]

        # Recover AES key
        rec_aes_key = crypto_utils.decrypt_aes_key_rsa(priv, encrypted_aes_key)

        network_utils.send_json_message(conn, {"status": "READY_FOR_DATA"})

        # Receive encrypted data
        enc_payload = network_utils.recv_exact(conn, enc_filesize)

        # Decrypt AES-GCM
        decryptor = crypto_utils.StreamingAESGCMDecryptor(rec_aes_key, nonce_val, tag_val)
        dec_payload = decryptor.update(enc_payload) + decryptor.finalize()

        # SHA256 verify
        calc_sha = crypto_utils.calculate_bytes_sha256(dec_payload)
        assert calc_sha.lower() == expected_sha.lower()

        # Save received file
        out_path = config.RECEIVED_FILES_DIR / "test_sample_received.txt"
        with open(out_path, "wb") as f:
            f.write(dec_payload)

        network_utils.send_json_message(conn, {"status": "SUCCESS", "message": "OK"})
        server_received_success = True
        conn.close()

    t = threading.Thread(target=receiver_worker, daemon=True)
    t.start()

    time.sleep(0.2)

    # Sender client simulation
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(("127.0.0.1", test_port))

    # Send Auth
    network_utils.send_json_message(client_sock, {
        "action": "AUTH",
        "username": "admin",
        "password": "securepassword123",
        "version": config.PROTOCOL_VERSION
    })
    auth_res = network_utils.recv_json_message(client_sock)
    assert auth_res["status"] == "AUTH_OK"
    rec_pub_key = auth_res["public_key"].encode('utf-8')

    # Encrypt file
    raw_sha256 = crypto_utils.calculate_sha256(str(sample_file_path))
    session_key = crypto_utils.generate_aes_key()
    session_nonce = crypto_utils.generate_gcm_nonce()
    enc_session_key = crypto_utils.encrypt_aes_key_rsa(rec_pub_key, session_key)

    enc_obj = crypto_utils.StreamingAESGCMEncryptor(session_key, session_nonce)
    with open(sample_file_path, "rb") as f:
        file_bytes = f.read()
    enc_data = enc_obj.update(file_bytes)
    final_chunk, enc_tag = enc_obj.finalize()
    full_enc_data = enc_data + final_chunk

    # Metadata
    network_utils.send_json_message(client_sock, {
        "action": "TRANSFER",
        "filename": "test_sample.txt",
        "enc_filesize": len(full_enc_data),
        "raw_filesize": len(file_bytes),
        "encrypted_aes_key": enc_session_key.hex(),
        "nonce": session_nonce.hex(),
        "tag": enc_tag.hex(),
        "sha256": raw_sha256
    })

    meta_res = network_utils.recv_json_message(client_sock)
    assert meta_res["status"] == "READY_FOR_DATA"

    # Send data
    client_sock.sendall(full_enc_data)

    final_ack = network_utils.recv_json_message(client_sock)
    assert final_ack["status"] == "SUCCESS"
    client_sock.close()
    server_sock.close()

    t.join(timeout=2.0)
    assert server_received_success is True

    # Cleanup temp sample file
    if sample_file_path.exists():
        os.remove(sample_file_path)

    print("[PASS] Full Socket End-to-End Encrypted File Transfer Completed!")
    print("\n==================================================")
    print("     ALL TESTS PASSED WITH 100% SUCCESS rate!     ")
    print("==================================================")

if __name__ == "__main__":
    run_test()
