package com.delvin;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import com.delvin.printer.Printer;
import java.util.Arrays;

public class SignParser {
    private byte[] marker = new byte[] { (byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE };
    private byte[] data;
    private byte[] sign;
    private boolean verbose = false;

    private BigInteger e;
    private BigInteger n;
    private BigInteger c;

    public SignParser() {
    };

    public SignParser(boolean verbose) {
        this.verbose = verbose;
    }

    public byte[] getDump(byte[] content, byte[] signature) {
        byte[] dump = this.generateDump(signature);
        byte[] result = new byte[content.length + dump.length];
        System.arraycopy(content, 0, result, 0, content.length);
        System.arraycopy(dump, 0, result, content.length, dump.length);
        return result;
    }

    public String bytesToHex(byte[] bytes) {
        char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    private byte[] generateDump(byte[] signature) {
        ByteBuffer out = ByteBuffer.allocateDirect(signature.length + Integer.BYTES * 3);
        out.put(this.marker);
        out.putInt(signature.length);
        out.put(signature);
        out.put(this.marker);
        out.rewind();
        byte[] tmp = new byte[out.remaining()];
        out.get(tmp);
        return tmp;
    }

    public void parse(byte[] content) {
        try {
            for (int i = 0; i < content.length; i++) {
                if (Arrays.equals(Arrays.copyOfRange(content, i, i + 4), this.marker)) {
                    Integer length = ByteBuffer.wrap(Arrays.copyOfRange(content, i + 4, i + 8)).getInt();
                    if (this.verbose)
                        Printer.info("Find length: " + length.toString());

                    if (Arrays.equals(Arrays.copyOfRange(content, i + 8 + length, i + 12 + length), this.marker)) {
                        Printer.success("Find signature in file");
                        this.data = Arrays.copyOfRange(content, 0, i);
                        this.sign = Arrays.copyOfRange(content, i, content.length);
                        this.initValues();
                        break;
                    }
                }
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            Printer.warning("File doesn't contain signature...");
            System.exit(1);
        }
    }

    private void initValues() {
        try {
            this.e = new BigInteger(Arrays.copyOfRange(this.sign, 8, 12));
            Integer nSize = ByteBuffer.wrap(Arrays.copyOfRange(this.sign, 12, 16)).getInt();
            this.n = new BigInteger(Arrays.copyOfRange(this.sign, 16, 16 + nSize));
            this.c = new BigInteger(Arrays.copyOfRange(this.sign, 16 + nSize, this.sign.length - 4));

            if (this.verbose) {
                Printer.info("e: " + this.e.toString(16));
                Printer.info("n: " + this.n.toString(16));
                Printer.info("c: " + this.c.toString(16));
                Printer.info("N size: " + nSize);
                Printer.info("Signature initialized successfully");
            }

        } catch (Exception e) {
            Printer.error("Signature initialization error, the signature has probably been changed");
            e.printStackTrace();
            System.exit(0);
        }
    }

    public byte[] getFileContent() {
        return this.data;
    }

    public BigInteger getExponent() {
        return this.e;
    }

    public BigInteger getModulo() {
        return this.n;
    }

    public BigInteger getSignature() {
        return this.c;
    }

}
