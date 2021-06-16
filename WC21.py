from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output
from Zeropoly import Zero_poly
from PoK import PoK

# type annotations'

pk_t = { 'w':G1, 'g_i':G1, 'h_i':G2, 'e_gg_alpha':GT}
mk_t = { 'h_omega':G2, 'alpha':ZR }
sk_t = { 'dk':G2 }
ct_t = { 'C1':G1, 'C2':G1, 'C3':GT, 'C1':G1 ,'C2':G1, 'C3':GT, 'S':str }
vk_t = { 'vk':G2 , 'X': G1, 'h':G2}
ek_t = { 'ek':G1 }
sgk_t = {'v':ZR }
sign_t = { 'R':G2, 'S':G1, 'T':G1, 'W':G1 }
Rand_t = { 'Rprime':G2, 'Sprime':G1, 'Tprime':G1, 'Wprime':G1}
ctt_t = { 'C1prime':G1, 'C2prime':G1, 'C3prime':GT, 'S':str }
class WC21(ABEnc):
         
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj
    
    @Output(pk_t, mk_t)    
    def RAgen(self,s,r):
        g, h, alpha, omega = group.random(G1), group.random(G2), group.random(ZR), group.random(ZR)
        g.initPP(); h.initPP()
        w = g ** omega; h_omega= h ** omega; e_gg_alpha = pair(w,h)
        g_i= {}
        for j in range(s+1):
            g_i[j] = g ** (alpha ** j)
        h_i= {}
        for j in range(r+1):
            h_i[j] = h ** (alpha ** j)
        pk = {'w':w, 'g_i':g_i, 'h_i':h_i, 'e_gg_alpha':e_gg_alpha}
        mk = {'h_omega':h_omega, 'alpha':alpha }
        return (pk, mk)

    @Input(pk_t)
    @Output(sgk_t,vk_t)
    def SAgen(self, pk):
        v = group.random(ZR); X = group.random(G1); h = group.random(G2)
        V = h ** v
        sgk = {'v':v}
        vk = {'vk':V, 'X':X, 'h':h}
        return (sgk, vk)

    @Input(pk_t, mk_t, str)
    @Output(sk_t)
    def DecKGen(self, pk, mk, ID):
        #id = objectToBytes(ID, group)
        dk = mk['h_omega'] ** (1 / (mk['alpha'] + group.hash(ID,ZR)))
        return { 'dk':dk }

    @Input(pk_t, sgk_t, vk_t, [str])
    @Output(ek_t, sign_t)
    def EncKGen(self, pk, sgk, vk, S):
        a=[]; Ek = 1
        for s in S:
            a.append(group.hash(s, ZR))
        (indices,coeff_mult) = Zero_poly(a,len(a)-1,[0],[1])
        Coeffs = list(reversed(coeff_mult))
        for i in range(len(indices)):
            Ek *= (pk['g_i'][i] ** Coeffs[i])  
        ek = {'ek':Ek}
        t = group.random(ZR)
        R = vk['h']**t
        S = (Ek ** (sgk['v']/t)) * (vk['X']**(1/t))
        T = (S ** (sgk['v']/t)) * (pk['g_i'][0]**(1/t))
        W = pk['g_i'][0]**(1/t)
        sign={'R':R, 'S':S, 'T':T, 'W':W}
        return (ek,sign)

    @Input(pk_t, vk_t, GT, ek_t, sign_t, [str])
    @Output(ct_t, Rand_t)
    def encrypt(self, pk, vk, M, ek, sign, S): 
        r = group.random(ZR); t=group.random(ZR) 
        C1 = pk['w'] ** r
        C2 = ek['ek'] ** r
        C3 = M * (pk['e_gg_alpha'] ** r)
        c1 = pk['w'] ** t
        c2 = ek['ek'] ** t
        c3 = pk['e_gg_alpha'] ** t
        ct = { 'C1':C1 ,'C2':C2, 'C3':C3, 'c1':c1 ,'c2':c2, 'c3':c3 , 'S':S }
        tprime = group.random(ZR)
        Rprime = sign['R'] ** (1/tprime)
        Sprime = sign['S'] ** tprime
        Tprime = (sign['T'] ** (tprime**2)) * (sign['W']**(tprime*(1-tprime)))
        Wprime = sign['W'] ** (1/tprime)
        Rand = { 'Rprime':Rprime, 'Sprime':Sprime, 'Tprime':Tprime, 'Wprime':Wprime}
        return (ct,Rand)
    

    @Input(pk_t, vk_t, ct_t, ek_t, Rand_t)
    @Output(ctt_t)
    def Sanitization(self, pk, vk, ct, ek, Rand):
        a = []; s = group.random(ZR)
        if pair(Rand['Sprime'],Rand['Rprime'])==pair(ek['ek'],vk['vk'])*pair(vk['X'],vk['h']) and \
             pair(Rand['Tprime'],Rand['Rprime'])==pair(Rand['Sprime'],vk['vk'])*pair(pk['g_i'][0],vk['h']):
            C1prime = ct['C1'] * (ct['c1'] ** s)
            C2prime = ct['C2'] * (ct['c2'] ** s)
            C3prime = ct['C3'] * (ct['c3'] ** s) 
            ctt = { 'C1prime':C1prime, 'C2prime':C2prime, 'C3prime':C3prime, 'S':ct['S'] }
            return (ctt)
        else:
            return print("You are not allowed to write this message")

    @Input(pk_t, sk_t, ctt_t, str)
    @Output(GT)
    def decrypt(self, pk, sk, ctt, ID):
        if ID in ctt['S']:
            A = list(set(ctt['S'])-set([ID]))
            a = []; z=1; H=1
            for i in A:
                a.append(group.hash(i, ZR))
                H *= group.hash(i, ZR)
            (indices,coeff_mult) = Zero_poly(a,len(a)-1,[0],[1])
            Coeffs = list(reversed(coeff_mult))
            for i in range(len(indices)):
                z *= pk['h_i'][i] ** (-Coeffs[i])
            z *= pk['h_i'][0] ** H
            V = (pair(ctt['C1prime'],z) * pair(ctt['C2prime'],sk['dk'])) ** (-1/H)
            return ctt['C3prime'] * V
        else:
            return print("You are not allowed to read this message")

