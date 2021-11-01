package com.delvin.cipher;

import java.math.BigInteger;
import java.util.Arrays;
import java.nio.ByteBuffer;

import com.delvin.printer.Printer;

public class PublicKey implements Key {
    private BigInteger n;
    private BigInteger e;
    private boolean verbose;

    public PublicKey(byte[] content, boolean verbose) {
        this.verbose = verbose;
        this.readKey(content);
    }

    public PublicKey(PrivateKey privateKey) {
        this.n = privateKey.getModulo();
        this.e = privateKey.getPublicExponent();
    }

    @Override
    public byte[] dumpKey() {
        byte[] n_arr = this.n.toByteArray();
        byte[] e_arr = this.e.toByteArray();
        ByteBuffer out = ByteBuffer.allocateDirect(Integer.BYTES + n_arr.length + e_arr.length);
        out.putInt(n_arr.length);
        out.put(n_arr);
        out.put(e_arr);
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
            this.e = new BigInteger(Arrays.copyOfRange(content, 4 + nSize, content.length));

            if (this.verbose) {
                Printer.info("Parse n: " + this.n.toString(16));
                Printer.info("Parse e: " + this.e.toString(16));
            }
        } catch (Exception e) {
            Printer.error("The format of the public key does not meet the requirements, it has probably been changed.");
            System.exit(1);
        }
    }
}
