package com.delvin.cipher;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.delvin.printer.Printer;

public class RSA {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private MessageDigest hash;
    private boolean verbose;

    public RSA(String hash, PrivateKey privateKey) throws NoSuchAlgorithmException {
        this.publicKey = new PublicKey(privateKey);
        this.privateKey = privateKey;
        this.hash = MessageDigest.getInstance(hash);
    }

    public RSA(String hash, Integer keySize, boolean verbose) throws NoSuchAlgorithmException {
        this.hash = MessageDigest.getInstance(hash);
        this.verbose = verbose;

        if (this.verbose)
            Printer.info("Generating keys...");
        this.privateKey = new PrivateKey(keySize / 2, verbose);
        this.publicKey = new PublicKey(privateKey);
    }

    public RSA(PublicKey publicKey) {
        this.publicKey = publicKey;
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

    public BigInteger decrypt(BigInteger signature, boolean verbose) {
        BigInteger res = signature.modPow(publicKey.getExponent(), publicKey.getModulo());
        if (verbose)
            Printer.info("Decrypted string: " + res.toString(16));
        return res;
    }
}
