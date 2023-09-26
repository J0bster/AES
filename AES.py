from collections import deque
import numpy as np
from Constants import SBOX, MODBOX, KEY

np.set_printoptions(formatter={"int": hex})

NB = 4
NR = 10
NK = 4


def SubBytes(state):
    for i, j in enumerate(state):
        y = 0
        for number in j:
            a = number >> 4
            b = number & 0x0F
            state[i][y] = SBOX[a][b]
            y += 1
    return state


def ShiftRows(state):
    for i, j in enumerate(state):
        items = deque(j)
        items.rotate(-i)
        state[i] = list(items)
    return state


def InvShiftRows(state):
    for i, j in enumerate(state):
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
            for a, i in zip(c, range(4)):
                answer ^= gmul(a, MODBOX[j][i])
            state[j][column] = answer
        column += 1
    return state


def gmul(a, b):
    if b == 1:
        return a
    tmp = (a << 1) & 0xFF
    if b == 2:
        return tmp if a < 128 else tmp ^ 0x1B
    if b == 3:
        return gmul(a, 2) ^ a


def AddRoundKey(state, roundkey):
    """ "Transformation in the Cipher and Inverse Cipher in which a Round
    Key is added to the State using an XOR operation. The length of a
    Round Key equals the size of the State (i.e., for Nb = 4, the Round
    Key length equals 128 bits/16 bytes).
    """
    for i in range(4):
        for j in range(4):
            state[i][j] ^= roundkey[j][i]
    return state


def Rotword(word):
    word = deque(word)
    word.rotate(-1)
    return np.array(word)


def Subword(word):
    i = 0
    for number in word:
        a = number >> 4
        b = number & 0x0F
        word[i] = SBOX[a][b]
        i += 1
    return word


def R_con(rounds):
    rcon_arr = np.array([[0x00] * 4 for _ in range(rounds)])
    rcon = 0x01
    rcon_arr[0][0] = rcon
    for i in np.arange(1, rounds):
        rcon = (rcon << 1) ^ (0x11B & -(rcon >> 7))
        rcon_arr[i][0] = rcon
    return rcon_arr


def KeyExpansion(key):
    w = np.array([[0] * 4 for _ in range(NB * (NR + 1))])
    Rcon = R_con(NR)
    for i in range(NK):
        w[i] = [(key[0][i]), (key[1][i]), (key[2][i]), (key[3][i])]

    for i in np.arange(NK, NB * (NR + 1)):
        temp = w[i - 1]
        if i % NK == 0:
            temp = Subword(Rotword(temp)) ^ Rcon[int(i / NK) - 1]
        w[i] = w[i - NK] ^ temp
    return w


def cypher(state):
    answer = state
    w = KeyExpansion(KEY)
    answer = AddRoundKey(state, w[0:NB])
    # print(answer)
    # print("")

    for round in np.arange(1, NR):
        answer = SubBytes(answer)
        answer = ShiftRows(answer)
        answer = Mixcolumns(answer)
        answer = AddRoundKey(answer, w[round * NB : ((round + 1) * NB)])
        # print(answer)
        # print("")

    answer = SubBytes(answer)
    answer = ShiftRows(answer)
    answer = AddRoundKey(answer, w[NR * NB : (NR + 1) * NB])

    return answer


if __name__ == "__main__":
    print("AES")
    # state = np.array([[0x19, 0xa0, 0x9a, 0xe9], [0x3d, 0xf4, 0xc6, 0xf8], [0xe3, 0xe2, 0x8d, 0x48], [0xbe, 0x2b, 0x2a, 0x08]])
    state = np.array(
        [
            [0x32, 0x88, 0x31, 0xE0],
            [0x43, 0x5A, 0x31, 0x37],
            [0xF6, 0x30, 0x98, 0x07],
            [0xA8, 0x8D, 0xA2, 0x34],
        ]
    )
    print(cypher(state))
