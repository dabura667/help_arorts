try:
    import os
    import hashlib
    import hmac
    import binascii
    import unicodedata

    __all__ = ['new', 'digest_size']

    __revision__ = "$Id$"

    import struct

    def u32(n):
        return n & 0xFFFFffffL

    rho = [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8]

    pi = [(9*i + 5) & 15 for i in range(16)]

    rl = [range(16)]
    rl += [[rho[j] for j in rl[-1]]]
    rl += [[rho[j] for j in rl[-1]]]
    rl += [[rho[j] for j in rl[-1]]]
    rl += [[rho[j] for j in rl[-1]]]

    rr = [list(pi)]
    rr += [[rho[j] for j in rr[-1]]]
    rr += [[rho[j] for j in rr[-1]]]
    rr += [[rho[j] for j in rr[-1]]]
    rr += [[rho[j] for j in rr[-1]]]

    f1 = lambda x, y, z: x ^ y ^ z

    f2 = lambda x, y, z: (x & y) | (~x & z)

    f3 = lambda x, y, z: (x | ~y) ^ z

    f4 = lambda x, y, z: (x & z) | (y & ~z)

    f5 = lambda x, y, z: x ^ (y | ~z)

    fl = [f1, f2, f3, f4, f5]

    fr = [f5, f4, f3, f2, f1]

    _shift1 = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8]
    _shift2 = [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7]
    _shift3 = [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9]
    _shift4 = [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6]
    _shift5 = [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5]

    sl = [[_shift1[rl[0][i]] for i in range(16)]]
    sl.append([_shift2[rl[1][i]] for i in range(16)])
    sl.append([_shift3[rl[2][i]] for i in range(16)])
    sl.append([_shift4[rl[3][i]] for i in range(16)])
    sl.append([_shift5[rl[4][i]] for i in range(16)])

    sr = [[_shift1[rr[0][i]] for i in range(16)]]
    sr.append([_shift2[rr[1][i]] for i in range(16)])
    sr.append([_shift3[rr[2][i]] for i in range(16)])
    sr.append([_shift4[rr[3][i]] for i in range(16)])
    sr.append([_shift5[rr[4][i]] for i in range(16)])

    _kg = lambda x, y: int(2**30 * (y ** (1.0 / x)))

    KL = [
        0,
        _kg(2, 2),
        _kg(2, 3),
        _kg(2, 5),
        _kg(2, 7),
    ]

    KR = [
        _kg(3, 2),
        _kg(3, 3),
        _kg(3, 5),
        _kg(3, 7),
        0,
    ]

    def rol(s, n):
        assert 0 <= s <= 31
        assert 0 <= n <= 0xFFFFffffL
        return u32((n << s) | (n >> (32-s)))

    initial_h = tuple(struct.unpack("<5L", "0123456789ABCDEFFEDCBA9876543210F0E1D2C3".decode('hex')))

    def box(h, f, k, x, r, s):
        assert len(s) == 16
        assert len(x) == 16
        assert len(r) == 16
        (a, b, c, d, e) = h
        for word in range(16):
            T = u32(a + f(b, c, d) + x[r[word]] + k)
            T = u32(rol(s[word], T) + e)
            (b, c, d, e, a) = (T, b, rol(10, c), d, e)
        return (a, b, c, d, e)

    def _compress(h, x):
        hl = hr = h

        for round in range(5):
            hl = box(hl, fl[round], KL[round], x, rl[round], sl[round])
            hr = box(hr, fr[round], KR[round], x, rr[round], sr[round])

        h = (u32(h[1] + hl[2] + hr[3]),
             u32(h[2] + hl[3] + hr[4]),
             u32(h[3] + hl[4] + hr[0]),
             u32(h[4] + hl[0] + hr[1]),
             u32(h[0] + hl[1] + hr[2]))

        return h

    def compress(h, s):
        assert len(s) % 64 == 0
        p = 0
        while p < len(s):
            h = _compress(h, struct.unpack("<16L", s[p:p+64]))
            p += 64
        assert p == len(s)
        return h

    class RIPEMD160(object):

        digest_size = 20

        def __init__(self, data=""):
            self.h = initial_h
            self.bytes = 0
            self.buf = ""
            self.update(data)

        def update(self, data):
            self.buf += data
            self.bytes += len(data)

            p = len(self.buf) & ~63
            if p > 0:
                self.h = compress(self.h, self.buf[:p])
                self.buf = self.buf[p:]
            assert len(self.buf) < 64

        def digest(self):

            length = (self.bytes << 3) & (2**64-1)

            assert len(self.buf) < 64
            data = self.buf + "\x80"
            if len(data) <= 56:
                assert len(data) <= 56
                data = struct.pack("<56sQ", data, length)
            else:
                assert len(data) <= 120
                data = struct.pack("<120sQ", data, length)

            h = compress(self.h, data)
            return struct.pack("<5L", *h)

        def hexdigest(self):
            return self.digest().encode('hex')

        def copy(self):
            obj = self.__class__()
            obj.h = self.h
            obj.bytes = self.bytes
            obj.buf = self.buf
            return obj

    def ripenew(data=""):
        return RIPEMD160(data)

    digest_size = 20

    Pcurve = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1
    N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    Acurve = 0; Bcurve = 7
    Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
    Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
    GPoint = (Gx,Gy)

    def modinv(a,n=Pcurve):
        lm, hm = 1,0
        low, high = a%n,n
        while low > 1:
            ratio = high/low
            nm, new = hm-lm*ratio, high-low*ratio
            lm, low, hm, high = nm, new, lm, low
        return lm % n

    def ECadd(a,b):
        LamAdd = ((b[1]-a[1]) * modinv(b[0]-a[0],Pcurve)) % Pcurve
        x = (LamAdd*LamAdd-a[0]-b[0]) % Pcurve
        y = (LamAdd*(a[0]-x)-a[1]) % Pcurve
        return (x,y)

    def ECdouble(a):
        Lam = ((3*a[0]*a[0]+Acurve) * modinv((2*a[1]),Pcurve)) % Pcurve
        x = (Lam*Lam-2*a[0]) % Pcurve
        y = (Lam*(a[0]-x)-a[1]) % Pcurve
        return (x,y)

    def EccMultiply(GenPoint,ScalarHex):
        if ScalarHex == 0 or ScalarHex >= N: raise Exception("Invalid Scalar/Private Key")
        ScalarBin = str(bin(ScalarHex))[2:]
        Q=GenPoint
        for i in range (1, len(ScalarBin)):
            Q=ECdouble(Q); 
            if ScalarBin[i] == "1":
                Q=ECadd(Q,GenPoint); 
        return (Q)

    __b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    __b58base = len(__b58chars)

    def b58encode(v):

        long_value = 0L
        for (i, c) in enumerate(v[::-1]):
            long_value += (256**i) * ord(c)

        result = ''
        while long_value >= __b58base:
            div, mod = divmod(long_value, __b58base)
            result = __b58chars[mod] + result
            long_value = div
        result = __b58chars[long_value] + result

        nPad = 0
        for c in v:
            if c == '\0': nPad += 1
            else: break

        return (__b58chars[0]*nPad) + result

    HEXCODE  = '0123 4567 89ab cdef'.replace(' ','')
    LETCODE  = 'asdf ghjk wert uion'.replace(' ','')

    def seed_to_bin(seed):
        lines = seed.replace(' ', '').split('<>')
        newlines = []
        new = ''
        for i in range(2):
            for j in range(len(lines[i])):
                new += HEXCODE[LETCODE.find(lines[i][j])]
            newlines.append(new)
            new = ''
        newseed = newlines[0][:32] + newlines[1][:32]
        chk1 = hashlib.sha256(hashlib.sha256(newlines[0][:32].decode('hex')).digest()).hexdigest()[:4]
        chk2 = hashlib.sha256(hashlib.sha256(newlines[1][:32].decode('hex')).digest()).hexdigest()[:4]
        assert chk1 == newlines[0][32:], "Invalid Checksum: Check to make sure you typed your Backup in right."
        assert chk2 == newlines[1][32:], "Invalid Checksum: Check to make sure you typed your Backup in right."
        return newseed


    def gen_addy_priv(MPK, secret, n, c=0):
        index = int(hashlib.sha256(hashlib.sha256("%d:%d:"%(n,c) + MPK.decode('hex')).digest()).hexdigest(),16)
        addy_pt = ECadd(EccMultiply(GPoint,index),(int(MPK[:64],16),int(MPK[64:],16)))
        privsec = (secret + index) % N
        assert EccMultiply(GPoint,privsec) == addy_pt, "Private Key and Generated Public Key don't match!"
        h160 = ripenew(hashlib.sha256(("04" + ("%064x" % addy_pt[0]) + ("%064x" % addy_pt[1])).decode('hex')).digest()).digest()
        h160chk = hashlib.sha256(hashlib.sha256(chr(0) + h160).digest()).digest()[:4]
        addy = b58encode(chr(0) + h160 + h160chk)
        
        privchk = hashlib.sha256(hashlib.sha256(chr(128) + ("%064x" % privsec).decode('hex')).digest()).digest()[:4]
        wifpriv = b58encode(chr(128) + ("%064x" % privsec).decode('hex') + privchk)
        
        return addy, wifpriv
    

    ##############################################################################################
    #
    print "Please type in your \"PrivHexBE\" from Armory that matched your PublicX and PublicY."
    print "Type in the first line, then the second line. It will ask for each line separately."
    print
    print "Also, for the second input, please paste in the \"Master Public Key\" from Electrum."
    print "We must check and make sure Electrum has the correct MPK that matches your Backup Phrase"
    print "from Armory, so open the watch-only wallet in Electrum, and \"Wallet\" > \"Master Public Key\""
    print "and paste that long number into the MPK input line."
    print
    print "Windows command window can only paste by right clicking the bar at the top, clicking \"Edit\","
    print "then clicking paste."
    print
    #
    
    bckup = raw_input("PrivHexBE? ")
    """bckup = raw_input("Armory Backup Phrase? (1st Line) ")
    bckup2 = raw_input("Armory Backup Phrase? (2nd Line) ")
    bckup = bckup + " <> " + bckup2"""
    print
    #'aagh hjfj sihk ietj giik wwai awtd uodh hnji <> soss uaku egod utai itos fijj ihgi jhau jtoo'
    #'aaghhjfjsihkietjgiikwwaiawtduodhhnji <> sossuakuegodutaiitosfijjihgijhaujtoo'
    #
    chkMPK = raw_input("Electrum MPK? ")
    #'5a09a3286873a72f164476bde9d1d8e5c2bc044e35aa47eb6e798e325a86417f7c35b61d9905053533e0b4f2a26eca0330aadf21c638969e45aaace50e4c0c87'
    #
    ##############################################################################################


    secpriv = int(bckup.replace(' ',''),16) #int(seed_to_bin(bckup),16)
    pt = EccMultiply(GPoint,secpriv)
    MPK = ("%064x" % pt[0]) + ("%064x" % pt[1])
    assert MPK == chkMPK, "Your MPK and the backup phrase MPK don't match."

    print
    print "Receive Address + Private Key"
    for i in range(5):
        addy, wifpriv = gen_addy_priv(MPK, secpriv, i)
        print addy, wifpriv
    print
    print "Change Address + Private Key"
    for i in range(3):
        addy, wifpriv = gen_addy_priv(MPK, secpriv, i, 1)
        print addy, wifpriv
    raw_input()
    
except Exception,e:
    print "ERROR: " + str(e)
    raw_input()
