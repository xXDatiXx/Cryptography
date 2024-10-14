# S-box
S_BOX = [
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
]

# RCON para expansión de claves
R_CON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def add_round_key(state, round_key):
    """Hace XOR entre el estado y la clave de ronda"""
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state

def sub_bytes(state):
    """Aplica la S-box a cada byte en el estado"""
    for i in range(4):
        for j in range(4):
            byte = state[i][j]
            x = (byte >> 4) & 0xF  # Parte alta (4 bits)
            y = byte & 0xF  # Parte baja (4 bits)
            state[i][j] = S_BOX[x][y]
    return state

def shift_rows(state):
    """Aplica el desplazamiento de filas a la matriz de estado"""
    state[1] = state[1][1:] + state[1][:1]  # Desplaza la segunda fila una posición
    state[2] = state[2][2:] + state[2][:2]  # Desplaza la tercera fila dos posiciones
    state[3] = state[3][3:] + state[3][:3]  # Desplaza la cuarta fila tres posiciones
    return state

def galois_mult(a, b):
    """Multiplicación en el campo de Galois para AES"""
    p = 0
    for counter in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1B  # Polinomio irreducible
        b >>= 1
    return p & 0xFF

def mix_single_column(a):
    """Aplica la operación MixColumns a una sola columna"""
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    temp = a[0]
    a[0] ^= t ^ galois_mult(a[0] ^ a[1], 2)
    a[1] ^= t ^ galois_mult(a[1] ^ a[2], 2)
    a[2] ^= t ^ galois_mult(a[2] ^ a[3], 2)
    a[3] ^= t ^ galois_mult(a[3] ^ temp, 2)
    return a

def mix_columns(state):
    """Aplica MixColumns a todo el estado"""
    for i in range(4):
        state[i] = mix_single_column(state[i])
    return state

def rot_word(word):
    """Desplaza una palabra de 4 bytes una posición a la izquierda"""
    return word[1:] + word[:1]

def sub_word(word):
    """Sustituye cada byte en una palabra usando la S-box"""
    return [S_BOX[byte >> 4][byte & 0x0F] for byte in word]

def key_expansion(key):
    """Genera las claves de ronda a partir de la clave inicial"""
    expanded_keys = [list(key[i:i+4]) for i in range(0, 16, 4)]
    
    for i in range(4, 44):  # Se generan 44 palabras
        temp = expanded_keys[i - 1]
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= R_CON[i // 4 - 1]  # XOR con RCON solo en el primer byte
        expanded_keys.append([expanded_keys[i - 4][j] ^ temp[j] for j in range(4)])
    
    # Unir en bloques de 4 palabras (16 bytes) para obtener cada clave de ronda
    return [expanded_keys[i:i+4] for i in range(0, len(expanded_keys), 4)]

def aes_round(state, round_key, is_final_round=False):
    """Ejecuta una ronda de AES. Si is_final_round es True, no se ejecuta MixColumns."""
    state = sub_bytes(state)
    state = shift_rows(state)
    if not is_final_round:
        state = mix_columns(state)
    state = add_round_key(state, round_key)
    return state

def aes_encrypt(state, key):
    """Cifra el estado usando el algoritmo AES-128 con la clave dada"""
    round_keys = key_expansion(key)
    
    # Ronda inicial: solo AddRoundKey
    state = add_round_key(state, round_keys[0])
    
    # Rondas 1 a 9: SubBytes, ShiftRows, MixColumns, AddRoundKey
    for i in range(1, 10):
        state = aes_round(state, round_keys[i])
    
    # Ronda 10 (final): SubBytes, ShiftRows, AddRoundKey (sin MixColumns)
    state = aes_round(state, round_keys[10], is_final_round=True)
    
    return state

# Estado y clave de ejemplo
state = [ # Esto es lo que estamos cifrando
    [0x32, 0x88, 0x31, 0xe0],
    [0x43, 0x5a, 0x31, 0x37],
    [0xf6, 0x30, 0x98, 0x07],
    [0xa8, 0x8d, 0xa2, 0x34]
]

key = [
    0x2b, 0x28, 0xab, 0x09, 0x7e, 0xae, 0xf7, 0xcf, 
    0x15, 0xd2, 0x15, 0x4f, 0x16, 0xa6, 0x88, 0x3c
]

# Cifrado
ciphertext = aes_encrypt(state, key)

# Mostrar el resultado cifrado
print("Ciphertext después de 10 rondas de AES:")
for row in ciphertext:
    print([hex(x) for x in row])
