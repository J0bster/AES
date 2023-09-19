from collections import deque
import numpy as np
from Constants import SBOX, MODBOX, ROUNDKEY
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
    """"Transformation in the Cipher and Inverse Cipher in which a Round
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


if __name__ == "__main__":
    print("AES")
    # state = np.array([[0x19, 0xa0, 0x9a, 0xe9], [0x3d, 0xf4, 0xc6, 0xf8], [0xe3, 0xe2, 0x8d, 0x48], [0xbe, 0x2b, 0x2a, 0x08]])
    state = np.array([[0x32, 0x88, 0x31, 0xe0], [0x43, 0x5a, 0x31, 0x37], [0xf6, 0x30, 0x98, 0x07], [0xa8, 0x8d, 0xa2, 0x34]])
    print(cypher(state))

