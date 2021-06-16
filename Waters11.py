'''
Brent Waters (Pairing-based)
 
| From: "Ciphertext-Policy Attribute-Based Encryption: An Expressive, Efficient, and Provably Secure Realization", Appendix C.
| Published in: 2008
| Available from: http://eprint.iacr.org/2008/290.pdf
| Notes: Security Assumption: parallel q-DBDHE. The sole disadvantage of this scheme is the high number of pairings
| that must be computed during the decryption process (2 + N) for N attributes mathing in the key.

* type:            ciphertext-policy attribute-based encryption (public key)
* setting:        Pairing

:Authors:    J Ayo Akinyele
:Date:            11/2010
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc
from openpyxl import Workbook
from charm.core.engine.util import serializeDict,objectToBytes
debug = False
class CPabe09(ABEnc):

    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, debug)        
        group = groupObj
                        
    def setup(self):
        g1, g2 = group.random(G1), group.random(G2)
        alpha, a = group.random(), group.random()        
        e_gg_alpha = pair(g1,g2) ** alpha
        msk = {'g1^alpha':g1 ** alpha, 'g2^alpha':g2 ** alpha}        
        pk = {'g1':g1, 'g2':g2, 'e(gg)^alpha':e_gg_alpha, 'g1^a':g1 ** a, 'g2^a':g2 ** a}
        return (msk, pk)
    

    def SAgen(self, pk):
        v = group.random(ZR); X = group.random(G1)
        V = pk['g2'] ** v
        sgk = {'v':v}
        vk = {'vk':V, 'X':X}
        return (sgk, vk)

    def keygen(self, pk, msk, attributes):        
        t = group.random()
        K = msk['g2^alpha'] * (pk['g2^a'] ** t)
        L = pk['g2'] ** t
        k_x = [group.hash(s, G1) ** t for s in attributes]
        K_x = {}
        for i in range(0, len(k_x)):
            K_x[ attributes[i] ] = k_x[i]
        key = { 'K':K, 'L':L, 'K_x':K_x, 'attributes':attributes }
        return key
    

    def EncKGen(self, pk, sgk, vk, policy_str):
        policy = util.createPolicy(policy_str)        
        p_list = util.getAttributeList(policy)
        ek = {}; S={}; T={}
        t = group.random(ZR)
        R = pk['g2'] ** t
        secret = group.random()
        shares = util.calculateSharesList(secret, policy)
        for i in range(len(p_list)):
            if shares[i][0] == p_list[i]:
               attr = shares[i][0].getAttribute() 
               ek[p_list[i]] = (group.hash(attr, G1))
               S[i] = (ek[p_list[i]] ** (sgk['v']/t)) * (vk['X']**(1/t))
               T[i] = (S[i] ** (sgk['v']/t)) * (pk['g1']**(1/t))
        ek = {'ek':ek}
        W = pk['g1']**(1/t)
        sign={'R':R, 'S':S, 'T':T, 'W':W}
        return (ek,sign)


    def encrypt(self, pk, M, policy_str,ek,sign):
        # Extract the attributes as a list
        policy = util.createPolicy(policy_str)        
        p_list = util.getAttributeList(policy)
        s = group.random()
        C_tilde = (pk['e(gg)^alpha'] ** s) * M
        C_0 = pk['g1'] ** s
        C, D, Sprime,Tprime = {}, {}, {}, {}
        secret = s
        tprime = group.random(ZR)
        shares = util.calculateSharesList(secret, policy)
        # ciphertext
        for i in range(len(p_list)):
            r = group.random()
            if shares[i][0] == p_list[i]:
               C[ p_list[i] ] = ((pk['g1^a'] ** shares[i][1]) * (ek['ek'][p_list[i]] ** -r))
               D[ p_list[i] ] = (pk['g2'] ** r)
               Sprime[i] = sign['S'][i] ** tprime
               Tprime[i] = (sign['T'][i] ** (tprime**2)) * (sign['W']**(tprime*(1-tprime)))
        if debug: print("SessionKey: %s" % C_tilde)
        ct={ 'C0':C_0, 'C':C, 'D':D , 'C_tilde':C_tilde, 'policy':policy_str, 'attribute':p_list }
        Rprime = sign['R'] ** (1/tprime)
        Wprime = sign['W'] ** (1/tprime)
        Rand = { 'Rprime':Rprime, 'Sprime':Sprime, 'Tprime':Tprime, 'Wprime':Wprime}
        return (ct,Rand)
    
    def Sanitization(self, pk, vk, ct, ek, Rand):
        policy = util.createPolicy(ct['policy'])        
        p_list = util.getAttributeList(policy)
        a = []; s = group.random(ZR)
        for i in range(len(p_list)):
            if pair(Rand['Sprime'][i],Rand['Rprime']) == pair(ek['ek'][p_list[i]],vk['vk'])*pair(vk['X'],pk['g2']) and \
             pair(Rand['Tprime'][i],Rand['Rprime']) == pair(Rand['Sprime'][i],vk['vk'])*pair(pk['g1'],pk['g2']):
                return ct
                #C1prime = ct['C1'] * (ct['c1'] ** s)
                #C2prime = ct['C2'] * (ct['c2'] ** s)
                #C3prime = ct['C3'] * (ct['c3'] ** s) 
            else:
                return print("You are not allowed to write this message")
        #return { 'C1prime':C1prime, 'C2prime':C2prime, 'C3prime':C3prime, 'S':ct['S'] }
        

    def decrypt(self, pk, sk, ct):
        policy = util.createPolicy(ct['policy'])
        pruned = util.prune(policy, sk['attributes'])
        if pruned == False:
            return print("You are not allowed to read this message")
        coeffs = util.getCoefficients(policy)
        numerator = pair(ct['C0'], sk['K'])
        
        # create list for attributes in order...
        k_x, w_i = {}, {}
        for i in pruned:
            j = i.getAttributeAndIndex()
            k = i.getAttribute()
            k_x[ j ] = sk['K_x'][k]
            w_i[ j ] = coeffs[j]
            #print('Attribute %s: coeff=%s, k_x=%s' % (j, w_i[j], k_x[j]))
            
        C, D = ct['C'], ct['D']
        denominator = 1
        for i in pruned:
            j = i.getAttributeAndIndex()
            denominator *= ( pair(C[j] ** w_i[j], sk['L']) * pair(k_x[j] ** w_i[j], D[j]) )   
        return ct['C_tilde'] / (numerator / denominator)

    #Get the eliptic curve with the bilinear mapping feature needed.
