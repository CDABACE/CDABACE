### Hi there 👋

**Cross-Domain Attribute-Based Access Control Encryption** [[1]](#1) enables to build an ACE construction from any Ciphertext-Policy Attribute-Based Encryption. 
The code is written in python under [charm-crypto](http://charm-crypto.io/) library. This framework enables rapid prototyping of advanced cryptosystems. It uses the Python programming language from the ground up to reduce development time and complexity, and to promote reuse of components.


The structure of this repository is as follows: 
  - Schemes 
    - Ours.py: Python code for the proposed fully constant CD-ABACE scheme in Fig. 2.
    - Testours.py: Python code to run "Ours.py" under a simple example.
    - WC21.py: Python code for Wang and Chow ACE scheme [[2]](#2).
    - TestWC21.py: Python code to run "WC21.py" under a simple example.
    - Waters11.py: Python code for a variation of Waters's CP-ABE scheme [[3]](#3).
    - TestWaters11.py: Python code to run "Waters11.py" under a simple example.
    - PoK.py: Python code for NIZKs used in the construction.
    - ZeroPoly.py: Python code for Zero-Polynomial defines in Def. 3.
## References
<a id="1">[1]</a> 
Sedaghat, Mahdi, and Bart Preneel.
"Cross-Domain Attribute-Based Access Control Encryption."
CANS 2021 (To appear)

<a id="2">[2]</a> 
Wang, Xiuhua, and Sherman SM Chow.
"Cross-Domain Access Control Encryption: Arbitrary-policy, Constant-size, Efficient."
IEEE Symposium on Security and Privacy (S&P) (2021)

<a id="3">[3]</a> 
Waters, Brent.
"Ciphertext-policy attribute-based encryption: An expressive, efficient, and provably secure realization."
In International Workshop on Public Key Cryptography, pp. 53-70. Springer, Berlin, Heidelberg, 2011.
