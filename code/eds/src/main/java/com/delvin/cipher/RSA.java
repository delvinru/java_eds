package com.delvin.cipher;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

import com.delvin.printer.Printer;

public class RSA {
    private BigInteger e = BigInteger.valueOf(0x10001);
    private BigInteger p;
    private BigInteger q;
    private BigInteger n;
    private BigInteger d;
    private BigInteger c;

    private MessageDigest hash;
    private Integer keySize;
    private boolean verbose;

    public RSA(String hash, Integer keySize, boolean verbose) throws NoSuchAlgorithmException {
        this.hash = MessageDigest.getInstance(hash);
        this.keySize = keySize / 2;
        this.verbose = verbose;
    }

    public RSA(BigInteger e, BigInteger n, BigInteger c, boolean verbose) {
        this.e = e;
        this.n = n;
        this.c = c;
        this.verbose = verbose;
    }

    public byte[] encrypt(byte[] content) {
        if (this.verbose)
            Printer.info("Compute hash...");

        this.hash.update(content, 0, content.length);
        BigInteger message = new BigInteger(1, this.hash.digest());

        if (this.verbose)
            Printer.info("Hash: " + message.toString(16));

        this.p = BigInteger.probablePrime(this.keySize, new Random());
        this.q = BigInteger.probablePrime(this.keySize, new Random());

        if (this.verbose) {
            Printer.info("p: " + this.p.toString(16));
            Printer.info("q: " + this.q.toString(16));
        }

        this.n = p.multiply(q);
        if (this.verbose)
            Printer.info("n: " + this.n.toString(16));

        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        if (this.verbose)
            Printer.info("phi: " + phi.toString(16));

        this.d = this.inverse(this.e, phi);
        if (this.verbose)
            Printer.info("d: " + this.d.toString(16));

        this.c = message.modPow(this.d, this.n);
        if (this.verbose)
            Printer.info("c: " + this.c.toString(16));

        byte[] n_arr = this.n.toByteArray();
        byte[] c_arr = this.c.toByteArray();
        ByteBuffer out = ByteBuffer.allocateDirect(Integer.BYTES * 2 + n_arr.length + c_arr.length);
        out.putInt(this.e.intValue());
        out.putInt(this.n.toByteArray().length);
        out.put(n_arr);
        out.put(c_arr);
        out.rewind();
        byte[] tmp = new byte[out.remaining()];
        out.get(tmp);
        return tmp;
    }

    public BigInteger decrypt() {
        BigInteger res = this.c.modPow(this.e, this.n);
        if (this.verbose)
            Printer.info("Hash: " + res.toString(16));
        return res;
    }

    private ArrayList<BigInteger> xgcd(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO))
            return new ArrayList<BigInteger>(Arrays.asList(a, BigInteger.ONE, BigInteger.ZERO));
        else {
            ArrayList<BigInteger> arr = xgcd(b, a.mod(b));
            return new ArrayList<>(
                    Arrays.asList(arr.get(0), arr.get(2), arr.get(1).subtract(a.divide(b).multiply(arr.get(2)))));
        }
    }

    private BigInteger inverse(BigInteger a, BigInteger mod) {
        ArrayList<BigInteger> values = this.xgcd(a, mod);
        if (values.get(0).compareTo(BigInteger.ONE) != 0)
            throw new ArithmeticException("Not found inverse mode");
        else
            return values.get(1).mod(mod);
    }
}
