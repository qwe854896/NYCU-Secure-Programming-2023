#!/usr/bin/env python3
from Crypto.Util.number import *
from sage.all import *

# n ~ 2 ** 2048
# pt = padding + FLAG
#    ~ 835     + 30 bytes
padding = b"Padding in cryptography is a fundamental concept employed to ensure that data, typically in the form of plaintext, aligns properly with the encryption algorithm's block size. This process is crucial for symmetric block ciphers like AES and asymmetric encryption algorithms such as RSA. Padding involves adding extra bits to the input data before encryption, making it fit neatly into fixed-size blocks. The primary purpose of padding is to prevent information leakage by ensuring that the last block of plaintext is always complete, even when the original data's size isn't a perfect multiple of the block size. Common padding schemes include PKCS#7, PKCS#1 (for RSA), and ANSI X.923, each with its rules for padding and unpadding data. Proper padding ensures data integrity, security, and compatibility within cryptographic protocols."

e = 3
n = 11548249006448728920152703839381630946834097081458641312395741399152626808167055308830597218237419306363812953570976143239712039037941209800604194908083149885941768218371746741812573578768412807189143962911312361667909189521442378332430658999991458388376075547304981934158525694587528155624390264161508298680598416212224037418377397597560818727159266535257243347737195812548494888452510974912762585150695881388036715559552242157015756455473208463066542053661043988897316002396230791287157322382659981842882278113445574922266102197380093864871418103716702341116793118630092030597784102701252267617442078055768183287429
ct = 10016669153906644953016660527326048255337800602435656916304698358749910229624738375584073093905785564737742726549033330343901680652357648652891913260149958947299067801907769873568759955053120633017158582128001396334187309835478967775943564724073809481988489791896725867047366927584419210464759674986336704398037888892734158765679221980466827060998749130113847401820986980535379266905587107992796676977541915779320084736207068268591500847603252838325486939367980604888710370629644796971859833251926677637185722683564847418746350226830775205063128441515048529918173084258483536354002888691012853231754416802134513394608

a = bytes_to_long(padding) * (1 << (8 * 30))
c = ct
N = n
R = 1 << (8 * 30)

# LLL algorithm to find the shortest vector in lattice basis
B = matrix(
    [
        [R**3, 3 * a * R * R, 3 * a * a * R, a**3 - c],
        [0, N * R * R, 0, 0],
        [0, 0, N * R, 0],
        [0, 0, 0, N],
    ],
)

B = B.LLL()

poly = B[0]
# F.<x> = PolynomialRing(ZZ)
# Q = (poly[0] // R^3) * x^3 + (poly[1] // R^2) * x^2 + (poly[2] // R) * x + (poly[3] // 1)
F = PolynomialRing(ZZ, names=('x',)); (x,) = F._first_ngens(1)
Q = (poly[Integer(0)] // R**Integer(3)) * x**Integer(3) + (poly[Integer(1)] // R**Integer(2)) * x**Integer(2) + (poly[Integer(2)] // R) * x + (poly[Integer(3)] // Integer(1))

print(Q.roots())

msg = Q.roots()[0][0]

print(long_to_bytes(msg))
