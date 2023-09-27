from collections import deque
import numpy as np
from Constants import SBOX, MODBOX, ROUNDKEY, RCON
np.set_printoptions(formatter={'int':hex})


def SubBytes(state):
    for i,j in enumerate(state):
        y = 0
        for number in j:
            a = number >> 4
            b = number & 0x0F
            state[i][y] = (SBOX[a][b])
            y += 1
    return state
        



def ShiftRows(state):
    for i,j in enumerate(state):
        items = deque(j)
        items.rotate(-i)
        state[i] = list(items)
    # print(state)
    return state

def InvShiftRows(state):
    for i,j in enumerate(state):
        items = deque(j)
        items.rotate(i)
        state[i] = list(items)
    # print(state)
    return state

def Mixcolumns(state):
    column = 0
    temp = np.copy(state.T)
    for c in temp:
        answer = 0
        for j in range(4):
            answer = 0
            for a,i in zip(c,range(4)):
                answer ^= gmul(a, MODBOX[j][i])
            state[j][column] = answer
        column += 1
    return state

def gmul(a, b):
    if b == 1:
        return a
    tmp = (a << 1) & 0xff
    if b == 2:
        return tmp if a < 128 else tmp ^ 0x1b
    if b == 3:
        return gmul(a, 2) ^ a
    

def AddRoundKey(state, roundkey):
    """"
    Transformation in the Cipher and Inverse Cipher in which a Round
    Key is added to the State using an XOR operation. The length of a
    Round Key equals the size of the State (i.e., for Nb = 4, the Round
    Key length equals 128 bits/16 bytes).
    """
    for i in range(4):
        for j in range(4):
            state[i][j] ^= roundkey[i][j]
    return state

def cypher(state):
    answer = state
    answer = AddRoundKey(state, ROUNDKEY)
    print(answer)
    for _ in range(9):
        answer = SubBytes(answer)
        answer = ShiftRows(answer)
        answer = Mixcolumns(answer)
        answer = AddRoundKey(answer, ROUNDKEY)
    return answer


def SubWord(word):
    for i,j in enumerate(word):
        a = j >> 4
        b = j & 0x0F
        word[i] = (SBOX[a][b])
    return word

def RotWord(word):
    word = np.roll(word, -1)
    return word

def XorWord(word1, word2):
    for i in range(4):
        word1[i] ^= word2[i]
    return word1

def KeyExpansion(key, Nk):
    """
    KeyExpansion is an algorithm that takes as input a four-word (16-byte)
    """
    i = 0
    Nb = 4
    Nr = 10
    w = [0] * Nb * (Nr + 1)

    while i < Nk:
        w[i] = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]
        i += 1
    print(w)
    i = Nk

    while i < Nb * (Nr + 1):
        temp = w[i-1]
        print(f"{i}temp: {temp}")
        if i % Nk == 0:
            temp = RotWord(temp)
            temp = SubWord(temp)
            # temp = XorWord(temp, RCON[int(i/Nk)])
            temp = [x ^ y for x, y in zip(temp, RCON[i//Nk])]
        elif Nk > 6 and i % Nk == 4:
            temp = SubWord(temp)
        w[i] = XorWord(w[i-Nk], temp)
        i += 1
    
    return w
    


if __name__ == "__main__":
    print("AES")
    # state = np.array([[0x19, 0xa0, 0x9a, 0xe9], [0x3d, 0xf4, 0xc6, 0xf8], [0xe3, 0xe2, 0x8d, 0x48], [0xbe, 0x2b, 0x2a, 0x08]])
    state = np.array([[0x32, 0x88, 0x31, 0xe0], [0x43, 0x5a, 0x31, 0x37], [0xf6, 0x30, 0x98, 0x07], [0xa8, 0x8d, 0xa2, 0x34]])
    # print(cypher(state))
    key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
    print(KeyExpansion(key, 6))


