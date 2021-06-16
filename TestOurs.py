from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from Ours import CD_ABACE

# type of pairing
groupObj = PairingGroup('BN254')
cpabe = CD_ABACE(groupObj)

# RA setup
U = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NINE', 'TEN']
(pk, mk) = cpabe.RAgen(10, U)

# SA setup
(sgk,vk) = cpabe.SAgen(pk)

# Encryption key generation
P = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE']
(ek,sign) = cpabe.EncKGen(pk, sgk, vk, P, U)
print("Signature :=>", sign)

# Decryption key generation
B = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX']
dk = cpabe.DecKGen(pk, mk, B, U)
print("dk :=>", dk)

# Encryption
rand_msg = groupObj.random(GT)
(ct, Rand) = cpabe.encrypt(pk, vk, rand_msg, ek, sign, P)
print("\nCiphertext...\n", ct)


# Sanitization
(ctt) = cpabe.Sanitization(pk, vk, ct, Rand)
print("\n Sanitized Ciphertext...\n", ctt)

# Decryption
rec_msg = cpabe.decrypt(pk, dk, ctt)
print("\nDecrypt...\n")


if rand_msg==rec_msg:
    print("\nIt is correct")
else:
    print("\nIt is wrong")
