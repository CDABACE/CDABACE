from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from Waters11 import CPabe09

# type of pairing
groupObj = PairingGroup('BN254')
cpabe = CPabe09(groupObj)
# RA setup
pol = '((four or three) and (three or one))' 
attr_list = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NINE', 'TEN']

m = groupObj.random(GT)
(msk, pk) = cpabe.setup()

# SA setup
(sgk,vk)=cpabe.SAgen(pk)


# Encryption key generation

(ek,sign) = cpabe.EncKGen(pk, sgk, vk, pol)


print("Signature :=>", sign)

# Decryption key generation
cpkey = cpabe.keygen(pk, msk, attr_list)
print("dk :=>", cpkey)

# Encryption
(cipher,Rand) = cpabe.encrypt(pk, m, pol,ek,sign)
print("\nCiphertext...\n", cipher)


# Sanitization
ctt = cpabe.Sanitization(pk,vk,cipher,ek,Rand)
print("\n Sanitized Ciphertext...\n", ctt)

# Decryption
orig_m = cpabe.decrypt(pk, cpkey, ctt)
print("\nDecrypt...\n")


if m == orig_m:
    print("\nIt is correct")
else:
    print("\nIt is wrong")
