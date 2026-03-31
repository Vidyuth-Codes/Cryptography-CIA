import numpy as np

# ==========================
# CONFIGURATION
# ==========================

# 2x2 Hill Cipher Key Matrix
KEY_MATRIX = np.array([[3, 3],
                       [2, 5]])

MOD = 26
HASH_LENGTH = 6   # Fixed length custom hash output

#
# 1) Why a Custom Hash Function Was Needed

'''Standard cryptographic hash functions such as:
SHA-256
SHA-1
MD5

produce outputs in:
1.hexadecimal format
2.digits + letters
3.long fixed-length strings

Example SHA-256 output:
2CF24DBA5FB0A30E26E83B2AC5B9E29E...

However, the Hill Cipher algorithm works only on alphabetic characters (A–Z) under modulo 26 arithmetic.
So directly using standard hash functions creates problems:
1.output contains digits
2.output is too long
3.requires conversion and truncation

To solve this compatibility issue, a custom alphabetic hash function was designed.'''

#Custom-Built Alphabetical Hash Function Explained
'''
The custom hash function always produces:

6 alphabetic characters
Example:
HELLO → VJXLZN
WORLD → QMDTFA

So:
1.fixed length ✅
2.A–Z only ✅
3.easy to append to plaintext ✅

Working:
Step 1: Convert Plaintext into Numeric Form
Eg. HELLO -> [7,4,11,11,14]
Step 2: Weighted Character Contribution
Each character contributes to the hash based on:

its alphabet value
its position in the text
the current hash character position being generated

This is done using:

(num+1)×(j+1+i)

Where:
num = numeric value of character
j = position of character in plaintext
i = current position of hash output character

Why this is done:
This ensures:
1.different characters contribute differently
2.same letters in different positions affect the hash differently
3.order of characters matters
Step 3: Positional Mixing

Additional mixing is added using:

accumulator+=length of text×(i+3)
and
accumulator+=sum of all character values×(i+1)

Why this is done:
This helps make the hash more sensitive to:
message length
total character composition
output position
This creates better variation in the hash.

Step 4: Modulo 26 Reduction
After accumulation, each hash character is reduced using:
hash_char = accumulator mod26
This ensures the result always lies between:
0 to 25
which directly maps to:
A to Z
This is the most important part because it makes the hash:
fully compatible with Hill Cipher

Step 5: Convert Numeric Hash to Alphabetic Hash
Finally, numeric hash values are converted back into letters.
[21, 9, 23, 11, 25, 13] -> VJXLZN

'''

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