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
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private MessageDigest hash;
    private boolean verbose;

    public RSA(String hash, Integer keySize, boolean verbose) throws NoSuchAlgorithmException {
        this.hash = MessageDigest.getInstance(hash);
        this.verbose = verbose;

        if (this.verbose)
            Printer.info("Generating keys...");
        this.privateKey = new PrivateKey(keySize / 2, verbose);
        this.publicKey = new PublicKey(privateKey);
    }

    public byte[] encrypt(byte[] content) {
        this.hash.update(content, 0, content.length);
        BigInteger message = new BigInteger(1, this.hash.digest());

        if (this.verbose)
            Printer.info("hash: " + message.toString(16));

        BigInteger c = message.modPow(privateKey.getPrivateExponent(), privateKey.getModulo());
        if (this.verbose)
            Printer.info("c: " + c.toString(16));

        return this.getDump(c);
    }

    private byte[] getDump(BigInteger c) {
        byte[] data = this.publicKey.dumpKey();
        byte[] c_arr = c.toByteArray();
        byte[] res = new byte[data.length + c_arr.length];
        System.arraycopy(data, 0, res, 0, data.length);
        System.arraycopy(c_arr, 0, res, data.length, c_arr.length);
        return res;
    }

    public byte[] getPrivateKeyDump() {
        return this.privateKey.dumpKey();
    }

    public byte[] getPublicKeyDump() {
        return this.publicKey.dumpKey();
    }

    // public BigInteger decrypt() {
    // BigInteger res = this.c.modPow(this.e, this.n);
    // if (this.verbose)
    // Printer.info("Decrypted string: " + res.toString(16));
    // return res;
    // }
}
