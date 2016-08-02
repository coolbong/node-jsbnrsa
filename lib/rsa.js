//---------------------------------------------------------------------------------------------
// http://www-cs-students.stanford.edu/~tjw/jsbn/
// rsa1
//---------------------------------------------------------------------------------------------
var BigInteger = require('./jsbn');
var SecureRandom = require('./rng');

function parseBigInt(str, r) {
    return new BigInteger(str, r);
}

function RSAKey() {
    this.n = null;
    this.e = 0;
    this.d = null;
    this.p = null;
    this.q = null;
    this.dmp1 = null;
    this.dmq1 = null;
    this.coeff = null;
}
function RSASetPublic(N, E) {
    if (N != null && E != null && N.length > 0 && E.length > 0) {
        var mod;
        var exp;
        if(Buffer.isBuffer(N)) {
            mod = N.toString('hex');
        } else {
            mod = N;
        }
        if(Buffer.isBuffer(E)) {
            exp = E.toString('hex');
        } else {
            exp = E;
        }
        this.n = parseBigInt(mod, 16);
        this.e = parseInt(exp, 16);

    } else {
        console.log('Invalid RSA public key');
    }
}
function RSADoPublic(x) {
    return x.modPowInt(this.e, this.n);
}
function RSAEncrypt(text) {
    var input;

    if(Buffer.isBuffer(text)) {
        input = text.toString('hex');
    } else {
        input = text;
    }

    var m = parseBigInt(input, 16);
    var c = this.doPublic(m);
    if (c == null)
        return null;
    var h = c.toString(16);
    if ((h.length & 1) == 1) {
        h = '0' + h;
    }

    h = h.toUpperCase();
    return h;
}


//---------------------------------------------------------------------------------------------
// rsa2
//---------------------------------------------------------------------------------------------

function RSASetPrivate(N, D) {
    if (N != null && D != null && N.length > 0 && D.length > 0) {
        var n;
        var e;
        var d;
        if(Buffer.isBuffer(N)) {
            n = N.toString('hex');
        } else {
            n = N;
        }


        if(Buffer.isBuffer(D)) {
            d = D.toString('hex');
        } else {
            d = D;
        }

        this.n = parseBigInt(n, 16);
        this.d = parseBigInt(d, 16);
    } else {
        console.log("Invalid RSA private key");
        //alert("Invalid RSA private key");
    }
}

function RSASetPrivateCrt(P, Q, DP, DQ, C) {
    if ((P != null) && (Q != null) && (DP != null) && (DQ != null) && (C != null)) {
        var p;
        var q;
        var dp;
        var dq;
        var c;
        if (Buffer.isBuffer(P)) {
            p = P.toString('hex');
        } else {
            p = P;
        }
        if (Buffer.isBuffer(Q)) {
            q = Q.toString('hex');
        } else {
            q = Q;
        }
        if (Buffer.isBuffer(DP)) {
            dp = DP.toString('hex');
        } else {
            dp = DP;
        }
        if (Buffer.isBuffer(DQ)) {
            dq = DQ.toString('hex');
        } else {
            dq = DQ;
        }
        if (Buffer.isBuffer(C)) {
            c = C.toString('hex');
        } else {
            c = C;
        }
        this.p = parseBigInt(p, 16);
        this.q = parseBigInt(q, 16);
        this.dmp1 = parseBigInt(dp, 16);
        this.dmq1 = parseBigInt(dq, 16);
        this.coeff = parseBigInt(c, 16);
    } else {
        console.log('Invalid RSA private Crt Key');
    }
}
function RSASetPrivateEx(N, E, D, P, Q, DP, DQ, C) {
    if (N != null && E != null && N.length > 0 && E.length > 0) {
        var n;
        var e;
        var d;
        var p;
        var q;
        var dp;
        var dq;
        var c;

        if (Buffer.isBuffer(N)) {
            n = N.toString('hex');
        } else {
            n = N;
        }

        if (Buffer.isBuffer(E)) {
            e = E.toString('hex');
        } else {
            e = E;
        }

        if (Buffer.isBuffer(D)) {
            d = D.toString('hex');
        } else {
            d = D;
        }

        if (Buffer.isBuffer(P)) {
            p = P.toString('hex');
        } else {
            p = P;
        }

        if (Buffer.isBuffer(Q)) {
            q = Q.toString('hex');
        } else {
            q = Q;
        }

        if (Buffer.isBuffer(DP)) {
            dp = DP.toString('hex');
        } else {
            dp = DP;
        }

        if (Buffer.isBuffer(DQ)) {
            dq = DQ.toString('hex');
        } else {
            dq = DQ;
        }

        if (Buffer.isBuffer(C)) {
            c = C.toString(C);
        } else {
            c = C;
        }

        this.n = parseBigInt(n, 16);
        this.e = parseInt(e, 16);
        this.d = parseBigInt(d, 16);
        this.p = parseBigInt(p, 16);
        this.q = parseBigInt(q, 16);
        this.dmp1 = parseBigInt(dp, 16);
        this.dmq1 = parseBigInt(dq, 16);
        this.coeff = parseBigInt(c, 16);
    } else {
        console.log("Invalid RSA private key");
    }

}
function RSAGenerate(B, E) {
    var b;
    var e;

    if (Buffer.isBuffer(B)) {
        b = B.toString('hex');
    } else {
        b = B;
    }

    if (Buffer.isBuffer(E)) {
        e = E.toString('hex');
    } else {
        e = E;
    }
    var rng = new SecureRandom();
    var qs = b >> 1;


    this.e = parseInt(e, 16);
    var ee = new BigInteger(e, 16);
    for (; ; ) {
        for (; ; ) {
            this.p = new BigInteger(b - qs, 1, rng);
            if (this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.p.isProbablePrime(10))
                break;
        }
        for (; ; ) {
            this.q = new BigInteger(qs, 1, rng);
            if (this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.q.isProbablePrime(10))
                break;
        }
        if (this.p.compareTo(this.q) <= 0) {
            var t = this.p;
            this.p = this.q;
            this.q = t;
        }
        var p1 = this.p.subtract(BigInteger.ONE);
        var q1 = this.q.subtract(BigInteger.ONE);
        var phi = p1.multiply(q1);
        if (phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
            this.n = this.p.multiply(this.q);
            this.d = ee.modInverse(phi);
            this.dmp1 = this.d.mod(p1);
            this.dmq1 = this.d.mod(q1);
            this.coeff = this.q.modInverse(this.p);
            break;
        }
    }
}

function RSADoPrivate(x) {
    if (this.p == null || this.q == null)
        return x.modPow(this.d, this.n);
    var xp = x.mod(this.p).modPow(this.dmp1, this.p);
    var xq = x.mod(this.q).modPow(this.dmq1, this.q);

    while (xp.compareTo(xq) < 0)
        xp = xp.add(this.p);
    return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
}

function RSADecrypt(ctext) {
    var input;
    if(Buffer.isBuffer(ctext)) {
        input = ctext.toString('hex');
    } else {
        input = ctext;
    }
    var c = parseBigInt(input, 16);
    var m = this.doPrivate(c);
    if (m == null)
        return null;

    var h = m.toString(16);
    if ((h.length & 1) == 1) {
        h = '0' + h;
    }
    h = h.toUpperCase();
    return h;
}

//rsa.js
RSAKey.prototype.doPublic = RSADoPublic;
RSAKey.prototype.setPublic = RSASetPublic;
RSAKey.prototype.encrypt = RSAEncrypt;

//rsa2.js
RSAKey.prototype.doPrivate = RSADoPrivate;
RSAKey.prototype.setPrivate = RSASetPrivate;
RSAKey.prototype.setPrivateEx = RSASetPrivateEx;
RSAKey.prototype.setPrivateCrt = RSASetPrivateCrt;
RSAKey.prototype.generate = RSAGenerate;
RSAKey.prototype.decrypt = RSADecrypt;

RSAKey.parseBigInt = parseBigInt;
RSAKey.BigInteger = BigInteger;

module.exports = RSAKey;