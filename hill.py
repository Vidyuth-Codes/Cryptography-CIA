import numpy as np

# ==========================
# CONFIGURATION
# ==========================

# 2x2 Hill Cipher Key Matrix
KEY_MATRIX = np.array([[3, 3],
                       [2, 5]])

MOD = 26
HASH_LENGTH = 6   # Fixed length custom hash output


# ==========================
# HELPER FUNCTIONS
# ==========================

def mod_inverse(a, m):
    """Find modular inverse of a under modulo m"""
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("Modular inverse does not exist")

def matrix_mod_inverse(matrix, modulus):
    """Find inverse of 2x2 matrix under modulo arithmetic"""
    det = int(round(np.linalg.det(matrix)))
    det = det % modulus

    det_inv = mod_inverse(det, modulus)

    # Adjugate matrix for 2x2
    adj = np.array([[matrix[1][1], -matrix[0][1]],
                    [-matrix[1][0], matrix[0][0]]])

    inv_matrix = (det_inv * adj) % modulus
    return inv_matrix

def clean_text(text):
    """Convert text to uppercase and remove non-alphabetic chars"""
    return ''.join([char.upper() for char in text if char.isalpha()])

def text_to_numbers(text):
    """Convert A-Z to 0-25"""
    return [ord(char) - ord('A') for char in text]

def numbers_to_text(numbers):
    """Convert 0-25 back to A-Z"""
    return ''.join([chr(num + ord('A')) for num in numbers])

def pad_text(text, block_size):
    """Pad text with X to fit block size"""
    while len(text) % block_size != 0:
        text += 'X'
    return text

# ==========================
# CUSTOM HASH FUNCTION
# ==========================

def custom_hash(text, hash_length=HASH_LENGTH):
   
    nums = text_to_numbers(text)

    # If text is empty, return default hash
    if len(nums) == 0:
        return "A" * hash_length

    hash_values = []

    for i in range(hash_length):
        accumulator = 0

        for j, num in enumerate(nums):
            # Weighted contribution of each character
            accumulator += (num + 1) * (j + 1 + i)

        # Add position-based mixing
        accumulator += len(nums) * (i + 3)
        accumulator += sum(nums) * (i + 1)

        # Mod 26 to stay within A-Z
        hash_char = accumulator % 26
        hash_values.append(hash_char)

    return numbers_to_text(hash_values)

# ==========================
# HILL CIPHER ENCRYPTION
# ==========================

def hill_encrypt(plaintext, key_matrix):
    """Encrypt text using Hill Cipher"""
    n = key_matrix.shape[0]
    plaintext = pad_text(plaintext, n)
    nums = text_to_numbers(plaintext)

    ciphertext_nums = []

    for i in range(0, len(nums), n):
        block = np.array(nums[i:i+n]).reshape(n, 1)
        encrypted_block = np.dot(key_matrix, block) % MOD
        ciphertext_nums.extend(encrypted_block.flatten())

    return numbers_to_text(ciphertext_nums)

# ==========================
# HILL CIPHER DECRYPTION
# ==========================

def hill_decrypt(ciphertext, key_matrix):
    """Decrypt text using Hill Cipher"""
    n = key_matrix.shape[0]
    inv_key = matrix_mod_inverse(key_matrix, MOD)
    nums = text_to_numbers(ciphertext)

    plaintext_nums = []

    for i in range(0, len(nums), n):
        block = np.array(nums[i:i+n]).reshape(n, 1)
        decrypted_block = np.dot(inv_key, block) % MOD
        plaintext_nums.extend(decrypted_block.flatten())

    return numbers_to_text(plaintext_nums)

# ==========================
# SENDER SIDE
# ==========================

def sender_process(message):
    """
    Sender:
    1. Clean plaintext
    2. Generate custom hash
    3. Append hash
    4. Encrypt all
    """
    cleaned_message = clean_text(message)
    hash_value = custom_hash(cleaned_message)

    combined_message = cleaned_message + hash_value

    ciphertext = hill_encrypt(combined_message, KEY_MATRIX)

    return cleaned_message, hash_value, combined_message, ciphertext

# ==========================
# RECEIVER SIDE
# ==========================

def receiver_process(ciphertext, original_message_length):
    """
    Receiver:
    1. Decrypt ciphertext
    2. Separate message and hash
    3. Recompute hash
    4. Verify integrity
    """
    decrypted_combined = hill_decrypt(ciphertext, KEY_MATRIX)

    # Remove any extra padding after decryption
    useful_length = original_message_length + HASH_LENGTH
    decrypted_combined = decrypted_combined[:useful_length]

    # Separate original message and appended hash
    extracted_message = decrypted_combined[:original_message_length]
    extracted_hash = decrypted_combined[original_message_length:original_message_length + HASH_LENGTH]

    # Generate fresh hash
    recalculated_hash = custom_hash(extracted_message)

    # Verify
    is_valid = extracted_hash == recalculated_hash

    return decrypted_combined, extracted_message, extracted_hash, recalculated_hash, is_valid

# ==========================
# MAIN PROGRAM
# ==========================

def main():
    print("==============================================")
    print("   HILL CIPHER WITH CUSTOM HASH FUNCTION")
    print("==============================================\n")

    plaintext = input("Enter the plaintext message: ")

    # Sender side
    original_message, hash_value, combined_message, ciphertext = sender_process(plaintext)

    print("\n----------- SENDER SIDE -----------")
    print("Original Plaintext      :", original_message)
    print("Generated Hash          :", hash_value)
    print("Plaintext + Hash        :", combined_message)
    print("Encrypted Ciphertext    :", ciphertext)

    # Receiver side
    decrypted_combined, extracted_message, extracted_hash, recalculated_hash, is_valid = receiver_process(
        ciphertext, len(original_message)
    )

    print("\n----------- RECEIVER SIDE -----------")
    print("Decrypted Combined Text :", decrypted_combined)
    print("Extracted Plaintext     :", extracted_message)
    print("Extracted Hash          :", extracted_hash)
    print("Recalculated Hash       :", recalculated_hash)

    print("\n----------- VERIFICATION -----------")
    if is_valid:
        print("✅ Integrity Verified: Message is authentic and unchanged.")
    else:
        print("❌ Integrity Check Failed: Message has been tampered with.")

# Run program
if __name__ == "__main__":
    main()
