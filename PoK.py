from charm.core.engine.util import objectToBytes
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair

class PoK():
    def __init__(self, groupObj):
        global util, group
        group = groupObj
    def prover1(self,g,y,x):
        r = group.random(ZR)
        t = g ** r
        c = group.hash(objectToBytes(y, group)+objectToBytes(t, group),ZR)
        z = c * x + r
        return { 'z':z, 't':t, 'y':y }
    def prover2(self,g,y,x,u):
        r = group.random(ZR)
        t = pair(g,u) ** r
        c = group.hash(objectToBytes(y, group)+objectToBytes(t, group)+objectToBytes(u, group),ZR)
        z = c * x + r
        return { 'z':z, 't':t, 'y':y }
    def verifier1(self, g, y, z, t):
        c = group.hash(objectToBytes(y, group)+objectToBytes(t, group),ZR)
        if (y**c) * t == g ** z:
            return 1
        else:
            return 0
    def verifier2(self, g, y, z, t, u):
        c = group.hash(objectToBytes(y, group)+objectToBytes(t, group)+objectToBytes(u, group),ZR)
        if (y**c) * t == pair(g,u) ** z:
            return 1
        else:
            return 0
