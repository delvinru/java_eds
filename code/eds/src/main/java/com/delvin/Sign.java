package com.delvin;

import com.delvin.cipher.RSA;
import com.delvin.printer.Printer;
import java.security.MessageDigest;
import java.util.Arrays;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;

public class Sign {
    private String hash;
    private Integer keySize;
    private String inFile;
    private String outFile;
    private boolean verbose;

    public Sign(Args args) {
        this.hash = args.getAlgorithm();
        this.keySize = args.getKeySize();
        this.inFile = args.getFileName();
        this.outFile = args.getOutFileName();
        this.verbose = args.getVerbose();
    }

    public void createSign() {
        try {
            File file = new File(this.inFile);
            byte[] content = Files.readAllBytes(file.toPath());
            RSA rsa = new RSA(hash, keySize, verbose);
            byte[] signature = rsa.encrypt(content);
            this.saveToFile(content, signature);
        } catch (Exception e) {
            Printer.error("Got error: " + e.toString());
        }
    }

    public void checkSign() {
        try {
            File file = new File(this.inFile);
            byte[] content = Files.readAllBytes(file.toPath());
            this.verifySign(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void saveToFile(byte[] content, byte[] signature) {
        File out = new File(this.outFile);
        try (FileOutputStream stream = new FileOutputStream(out)) {
            stream.write(new SignParser().getDump(content, signature));
        } catch (IOException e) {
            Printer.error("Can't save data to file");
            System.exit(1);
        }
        Printer.success("Document " + this.inFile + " signed");
        Printer.success("Saved to " + this.outFile);
    }

    private void verifySign(byte[] content) {
        SignParser parser = new SignParser(this.verbose);
        parser.parse(content);
        RSA rsa = new RSA(parser.getExponent(), parser.getModulo(), parser.getSignature(), this.verbose);
        byte[] fileContent = parser.getFileContent();
        BigInteger testSignature = rsa.decrypt();
        String[] hashes = { "MD5", "SHA-1", "SHA-256", "SHA-512" };
        try {
            for (String hash_type : hashes) {
                MessageDigest hash = MessageDigest.getInstance(hash_type);
                hash.update(fileContent, 0, fileContent.length);
                System.out.println("h: " + new BigInteger(hash.digest()).toString(16));

                // Very strange shit, false for equals values
                // TODO: look up
                if (testSignature.equals(new BigInteger(hash.digest()))) {
                    System.out.println("laksdjfalskdfj");
                    Printer.success("The file has not been modified, the signature is correct.");
                    break;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
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
}