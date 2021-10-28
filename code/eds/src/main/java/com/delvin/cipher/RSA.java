package com.delvin.cipher;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

import javax.print.event.PrintEvent;

import com.delvin.printer.Printer;

public class RSA implements Cipher {
    private BigInteger e = BigInteger.valueOf(0x10001);

    private MessageDigest hash;
    private Integer keySize;
    private File inFile;
    private File outFile;
    private boolean verbose;

    public RSA(String hash, Integer keySize, String inFile, String outFile, boolean verbose)
            throws NoSuchAlgorithmException {
        this.hash = MessageDigest.getInstance(hash);
        this.keySize = keySize / 2;
        this.inFile = new File(inFile);
        this.outFile = new File(outFile);
        this.verbose = verbose;
    }

    @Override
    public void encrypt() throws IOException {
        if (this.verbose)
            Printer.info("Compute hash...");

        byte[] content = Files.readAllBytes(this.inFile.toPath());
        this.hash.update(content, 0, content.length);
        BigInteger message = new BigInteger(1, this.hash.digest());

        if (this.verbose)
            Printer.info("Hash: " + message.toString(16));

        BigInteger p = BigInteger.probablePrime(this.keySize, new Random());
        BigInteger q = BigInteger.probablePrime(this.keySize, new Random());

        if (this.verbose) {
            Printer.info("p: " + p.toString(16));
            Printer.info("q: " + q.toString(16));
        }

        BigInteger n = p.multiply(q);
        if (this.verbose)
            Printer.info("n: " + n.toString(16));

        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        if (this.verbose)
            Printer.info("phi: " + phi.toString(16));

        BigInteger d = this.inverse(this.e, phi);
        if (this.verbose)
            Printer.info("d: " + d.toString(16));

        BigInteger c = message.modPow(this.e, n);
        if (this.verbose)
            Printer.info("c: " + c.toString(16));
    }

    @Override
    public void decrypt() {

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
