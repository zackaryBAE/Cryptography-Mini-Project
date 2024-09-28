# Substitution box (S-box)
sbox = {
    0b0000: 0b1110, 0b0001: 0b0100, 0b0010: 0b1101, 0b0011: 0b0001,
    0b0100: 0b0010, 0b0101: 0b1111, 0b0110: 0b1011, 0b0111: 0b1000,
    0b1000: 0b0011, 0b1001: 0b1010, 0b1010: 0b0110, 0b1011: 0b1100,
    0b1100: 0b0101, 0b1101: 0b1001, 0b1110: 0b0000, 0b1111: 0b0111
}

# Permutation table
perm_table = [1, 5, 2, 0, 3, 7, 4, 6]

# S-box substitution function
def substitute_4bit(value):
    return sbox[value]

# Permutation function
def permute_8bit(block):
    permuted_block = 0
    for i, pos in enumerate(perm_table):
        permuted_block |= ((block >> pos) & 1) << i
    return permuted_block

# Feistel function
def feistel_function(right, key):
    return right ^ key

# Encrypt 8-bit block (single round Feistel network)
def encrypt_8bit_block(block, key):
    # Split the block into left (L) and right (R)
    left = (block >> 4) & 0xF  # Left 4 bits
    right = block & 0xF         # Right 4 bits
    
    # Feistel round
    right_sub = substitute_4bit(right)
    new_left = left ^ right_sub
    
    # Combine the halves and permute
    combined = (new_left << 4) | right
    return permute_8bit(combined)

# ECB mode encryption
def ecb_encrypt(plaintext, key):
    ciphertext = []
    for block in plaintext:
        encrypted_block = encrypt_8bit_block(block, key)
        ciphertext.append(encrypted_block)
    return ciphertext

# ECB mode decryption (same as encryption for this simple cipher)
def ecb_decrypt(ciphertext, key):
    plaintext = []
    for block in ciphertext:
        decrypted_block = encrypt_8bit_block(block, key)  # Same function for decrypt
        plaintext.append(decrypted_block)
    return plaintext

# CBC mode encryption
def cbc_encrypt(plaintext, key, iv):
    ciphertext = []
    previous_block = iv  # IV used for the first block
    
    for block in plaintext:
        xor_block = block ^ previous_block  # XOR with previous ciphertext (or IV)
        encrypted_block = encrypt_8bit_block(xor_block, key)
        ciphertext.append(encrypted_block)
        previous_block = encrypted_block  # Update previous block with current ciphertext
    
    return ciphertext

# CBC mode decryption
def cbc_decrypt(ciphertext, key, iv):
    plaintext = []
    previous_block = iv  # IV used for the first block
    
    for block in ciphertext:
        decrypted_block = encrypt_8bit_block(block, key)  # Decrypt block
        xor_block = decrypted_block ^ previous_block  # XOR with previous ciphertext (or IV)
        plaintext.append(xor_block)
        previous_block = block  # Update previous block
    
    return plaintext

# Padding function for plaintext to fit 8-bit blocks
def pad_plaintext(plaintext, block_size=8):
    padding_length = block_size - (len(plaintext) % block_size)
    return plaintext + '0' * padding_length  # Pad with zeros

# Test with a sample plaintext and key
plaintext_message = "101010101100"  # 12-bit message (needs padding)
key = 0b11001100  # 8-bit key

# Pad plaintext and convert into 8-bit blocks
plaintext_message = pad_plaintext(plaintext_message)
plaintext_blocks = [int(plaintext_message[i:i+8], 2) for i in range(0, len(plaintext_message), 8)]

# ECB encryption and decryption
ciphertext_ecb = ecb_encrypt(plaintext_blocks, key)
print(f"ECB Ciphertext: {[f'{block:08b}' for block in ciphertext_ecb]}")
decrypted_ecb = ecb_decrypt(ciphertext_ecb, key)
print(f"ECB Decrypted: {[f'{block:08b}' for block in decrypted_ecb]}")

# CBC encryption and decryption
iv = 0b11110000  # Initialization vector
ciphertext_cbc = cbc_encrypt(plaintext_blocks, key, iv)
print(f"CBC Ciphertext: {[f'{block:08b}' for block in ciphertext_cbc]}")
decrypted_cbc = cbc_decrypt(ciphertext_cbc, key, iv)
print(f"CBC Decrypted: {[f'{block:08b}' for block in decrypted_cbc]}")
