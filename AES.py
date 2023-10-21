# Introduction to Security: Implementation of the AES algorithm
#
#
#
# Student names: Emmanuel Mukeh, Job Stouthart
# Student numbers: 13461869, 13999788
# Date: 11/10/2023
# Comments: The document with the AES guidlines used for this implementation is https://doi.org/10.6028/NIST.FIPS.197-upd1
# Motivation for design choices: We chose to implement the AES-128 in python mainl y because in python you can easily use np.arrays
#                                in the calculations for this algorithm and it has a lot of pre-made functions that came in handy for
#                                the transformations that we implemented. The ciphertext are given as double arrays that represent a 4x4
#                                table with 4 byte words in each column, so each inner array (row) contains either the 1st, 2nd, 3rd
#                                or 4th elements of each column. This is done so because it makes it visually look like a 4x4 table,
#                                which made it easier for us to compare the transformation functions with the document describing them.
#                                The examples in the document were also represented in 4x4 tables which made comparing the actual
#                                process of the cipher easier too. The key is also a double array, but in the key expansion function
#                                the key schedule generated and returned as a  double array where the columns are contained in the
#                                inner arrays, so the rows are the columns. This was done because it made it simpler to shift through
#                                the columns but mainly because we have to xor them with a previous column and R-constants after applying
#                                transformations, which is easily done using the xor operator on the whole column since it is an np.array.


from collections import deque
import numpy as np
from Constants import SBOX, MODBOX

# Set that integers are printed as hexadecimals
np.set_printoptions(formatter={"int": hex})

# Constants for AES algorithm
NB = 4  # Number of columns (32-bit, i.e. 4-byte, words) comprising the State
NR = 10  # Number of rounds
NK = 4  # Number of 32-bit words comprising the Cipher Key


def SubBytes(state):
    """Substitutes every byte in the State using the imported substitution
    table (S-box) and returns that State."""

    for x, row in enumerate(state):
        y = 0

        for val in row:
            # Checks y (column) index in the S-box for a value using the and operator with 0x0F since y goes up to 0x0F (= 1111 binary).
            sbox_y = val & 0x0F
            # Right-shift of 4 for to get x (row). Thus val = 0x10 (= 10000 binary), which is 1 greater then 0x0F, gets x = 0x01 (2nd row).
            sbox_x = val >> 4
            state[x][y] = SBOX[sbox_x][sbox_y]
            y += 1
    return state


def ShiftRows(state):
    """Shifts rows of a State n amount of times depending on the index of
    the row and returns that State."""

    for i, j in enumerate(state):
        items = deque(j)
        items.rotate(-i)
        state[i] = list(items)
    return state


def Mixcolumns(state):
    """Multiplies each column of the state with the imported ModBox using galios field
    multiplication and returns that State."""
    i_column = 0
    tmp = np.copy(state.T)

    # for every byte in the column, the multiplication is done with the values in the modbox
    for column in tmp:
        for j in range(4):
            result = 0
            for byte, i in zip(column, range(4)):
                result ^= gmul(byte, MODBOX[j][i])
            state[j][i_column] = result
        i_column += 1
    return state


def gmul(a, b):
    """Calculates Galios field modulo multiplication between byte a and b (which can be
    either 1, 2 or 3 because those are the values the ModBox is comprised of)"""
    if b == 1:
        return a
    if b == 2:
        # Left shift which is the first step for modulo multiplication, also check if the result is below 256 (& 0xFF)
        xtime = (a << 1) & 0xFF
        # If a is smaller then 0x80 (128) then the modulo is already reduced, if not it can be reduced by XOR'ing with 0x1B
        return xtime if a < 128 else xtime ^ 0x1B
    if b == 3:
        # Xor a with xtime modulo multiplication since {a}{03} = {a}{x + 1} = {a}{02} ^ {a}
        return gmul(a, 2) ^ a


def AddRoundKey(state, roundkey):
    """Adds the RoundKey to the State using an XOR operation and returns the state.
    The length of a Round Key equals the size of the State (NB)."""

    for i in range(NB):
        for j in range(NB):
            state[i][j] ^= roundkey[j][i]
    return state


def Rotword(word):
    """Rolls a word (column) of a State and returns the word."""

    word = np.roll(word, -1)
    return word


def Subword(word):
    """Does the SubBytes substitution on a single word (column) of a State and returns the word."""

    y = 0
    for val in word:
        sbox_y = val & 0x0F
        sbox_x = val >> 4
        word[y] = SBOX[sbox_x][sbox_y]
        y += 1
    return word


def R_con(rounds):
    """Calculates the round constants (RCON) that is needed in the key expansion and returns them in an array."""

    rcon_arr = np.array([[0x00] * 4 for _ in range(rounds)])
    rcon = 0x01
    rcon_arr[0][0] = rcon  # First round constant is set.

    # This loop calculates the next round constant based on the previous one (see https://crypto.stackexchange.com/a/2420)
    for i in np.arange(1, rounds):
        rcon = (rcon << 1) ^ (0x11B & -(rcon >> 7))
        rcon_arr[i][0] = rcon
    return rcon_arr


def KeyExpansion(key):
    """Expands key in to an array, w, containing a key for each round (incl. initial and final) and returns w."""

    w = np.array([[0] * 4 for _ in range(NB * (NR + 1))])
    Rcon = R_con(NR)

    # Put the Cipher key in the array for the inital round
    for i in range(NK):
        w[i] = [(key[0][i]), (key[1][i]), (key[2][i]), (key[3][i])]

    # Calculates the key for the next rounds based on the first and last column of previous key
    for i in np.arange(NK, NB * (NR + 1)):
        tmp = w[i - 1]
        if i % NK == 0:
            # If the ith column of the array is the first column of a round key then implement transformations
            tmp = Subword(Rotword(tmp)) ^ Rcon[int(i / NK) - 1]
        w[i] = w[i - NK] ^ tmp
    return w


def HexArray(length, input):
    """Transforms a hexadecimal input to an nump array of the correct size"""
    arr = np.array([[0x00] * 4 for _ in range(length)])
    i = 0
    j = 0
    for index, val in np.ndenumerate(arr):
        arr[index[0], index[1]] = int("0x" + input[i * 8 + j] + input[i * 8 + 1 + j], 0)
        i += 1
        if i == 4:
            j += 2
            i = 0
    return arr


def HexFormat(input):
    """Formats an numpy array to the hexadecimal format"""
    hexstr = ""
    for col in range(len(input[0])):
        for row in range(len(input)):
            hexstr += str(f"{input[row][col]:x}")
    return hexstr


def cypher(input, key_input):
    state = HexArray(NB, input)
    key = HexArray(NK, key_input)

    w = KeyExpansion(key)
    # Initial round, only add roundkey
    state = AddRoundKey(state, w[0:NB])

    for round in np.arange(1, NR):
        state = SubBytes(state)
        state = ShiftRows(state)
        state = Mixcolumns(state)
        state = AddRoundKey(state, w[round * NB : ((round + 1) * NB)])

    # Final round, no Mix Collumns
    state = SubBytes(state)
    state = ShiftRows(state)
    state = AddRoundKey(state, w[NR * NB : (NR + 1) * NB])
    return HexFormat(state)


if __name__ == "__main__":
    # Create ciphertext (4 x NB)
    input = "3243f6a8885a308d313198a2e0370734"
    key = "2b7e151628aed2a6abf7158809cf4f3c"

    print(f" input: {input}\n", f"key: {key}\n\n", f"output: {cypher(input, key)}")
