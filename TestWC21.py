from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from WC21 import WC21



groupObj = PairingGroup('BN254')
cpabe = WC21(groupObj)
S = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NINE', 'TEN']
R = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NINE', 'TEN']

(pk, mk) = cpabe.RAgen(len(S),len(R))
(sgk,vk) = cpabe.SAgen(pk)
ID = 'ONE'
(ek,sign) = cpabe.EncKGen(pk, sgk, vk, S)
dk = cpabe.DecKGen(pk, mk, ID)
print("dk :=>", dk)
rand_msg = groupObj.random(GT)
(ct, Rand) = cpabe.encrypt(pk, vk, rand_msg, ek, sign, S)
print("\nCiphertext...\n", ct)
(ctt) = cpabe.Sanitization(pk, vk, ct, ek, Rand)
print("\n Sanitized Ciphertext...\n", ctt)
rec_msg = cpabe.decrypt(pk, dk, ctt,ID)
print("\nDecrypt...\n")
print(rec_msg)
if rand_msg==rec_msg:
    print("\nIt is correct")
else:
    print("\nIt is wrong")

