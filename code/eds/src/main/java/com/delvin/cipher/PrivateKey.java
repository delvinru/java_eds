package com.delvin.cipher;

import java.util.ArrayList;
import java.util.Arrays;
import java.nio.ByteBuffer;

import java.math.BigInteger;
import java.util.Random;

import com.delvin.printer.Printer;

/**
 * Class for generating PrivateKey for RSA Cipher
 */
public class PrivateKey implements Key {
    private BigInteger e = BigInteger.valueOf(0x10001);
    private BigInteger p;
    private BigInteger q;
    private BigInteger phi;
    private BigInteger d;
    private BigInteger n;

    private boolean verbose;

    /**
     * @param keySize - Initialiaze p and q with this keySize
     */
    public PrivateKey(Integer keySize, boolean verbose) {
        this.verbose = verbose;
        p = BigInteger.probablePrime(keySize, new Random());
        q = BigInteger.probablePrime(keySize, new Random());
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        d = this.inverse(e, phi);
        n = p.multiply(q);

        if (this.verbose) {
            Printer.info("p: " + p.toString(16));
            Printer.info("q: " + p.toString(16));
            Printer.info("d: " + d.toString(16));
            Printer.info("n: " + n.toString(16));
        }
    }

    @Override
    public byte[] dumpKey() {
        byte[] n_arr = this.n.toByteArray();
        byte[] d_arr = this.d.toByteArray();
        ByteBuffer out = ByteBuffer.allocateDirect(Integer.BYTES + n_arr.length + d_arr.length);
        out.putInt(n_arr.length);
        out.put(n_arr);
        out.put(d_arr);
        out.rewind();
        byte[] tmp = new byte[out.remaining()];
        out.get(tmp);
        return tmp;
    }

    @Override
    public void readKey(byte[] content) {
        try {
            Integer nSize = ByteBuffer.wrap(Arrays.copyOfRange(content, 0, 4)).getInt();
            this.n = new BigInteger(Arrays.copyOfRange(content, 4, 4 + nSize));
            this.d = new BigInteger(Arrays.copyOfRange(content, 4 + nSize, content.length));

            if (this.verbose) {
                Printer.info("Parse d: " + this.d.toString(16));
                Printer.info("Parse n: " + this.n.toString(16));
            }
        } catch (Exception e) {
            Printer.error(
                    "The format of the private key does not meet the requirements, it has probably been changed.");
            System.exit(1);
        }
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

    public BigInteger getModulo() {
        return this.n;
    }

    public BigInteger getPrivateExponent() {
        return this.d;
    }

    public BigInteger getPublicExponent() {
        return this.e;
    }
}
