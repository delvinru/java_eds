package com.delvin;

import com.delvin.cipher.RSA;
import com.delvin.printer.Printer;
import java.security.MessageDigest;
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
    private String publicKeyFile;
    private String privateKeyFile;
    private boolean verbose;
    private String[] hashes;

    public Sign(Args args) {
        this.hash = args.getAlgorithm();
        this.keySize = args.getKeySize();
        this.inFile = args.getFileName();
        this.outFile = args.getOutFileName();
        this.verbose = args.getVerbose();
        this.hashes = args.getAllHashes();
        this.publicKeyFile = args.getPublicKeyFile();
        this.privateKeyFile = args.getPrivateKeyFile();
    }

    public void createSign() {
        try {
            File file = new File(this.inFile);
            byte[] content = Files.readAllBytes(file.toPath());

            RSA rsa = new RSA(hash, keySize, verbose);
            byte[] signature = rsa.encrypt(content);

            byte[] privateKeyDump = rsa.getPrivateKeyDump();
            byte[] publicKeyDump = rsa.getPublicKeyDump();

            this.saveToFile(content, signature);

            this.saveKey(this.publicKeyFile, publicKeyDump);
            this.saveKey(this.privateKeyFile, privateKeyDump);

        } catch (Exception e) {
            Printer.error("Got error: " + e.toString());
        }
    }

    // public void checkSign() {
    //     try {
    //         File file = new File(this.inFile);
    //         byte[] content = Files.readAllBytes(file.toPath());
    //         this.verifySign(content);
    //     } catch (Exception e) {
    //         e.printStackTrace();
    //     }
    // }

    // public void generateKeyPair() {

    // }

    private void saveKey(String filename, byte[] content) {
        File out = new File(filename);
        try (FileOutputStream stream = new FileOutputStream(out)) {
            stream.write(content);
        } catch (IOException e) {
            Printer.error("Can't save data to file: " + filename);
            System.exit(1);
        }
        Printer.success("Key saved: " + filename);
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

    // private void verifySign(byte[] content) {
    //     SignParser parser = new SignParser(this.verbose);
    //     parser.parse(content);
    //     RSA rsa = new RSA(parser.getExponent(), parser.getModulo(), parser.getSignature(), this.verbose);

    //     byte[] fileContent = parser.getFileContent();
    //     BigInteger decryptedHash = rsa.decrypt();
    //     String[] hashes = this.hashes;

    //     boolean flag = false;
    //     try {
    //         for (String hash_type : hashes) {
    //             MessageDigest tmpHash = MessageDigest.getInstance(hash_type);
    //             tmpHash.update(fileContent, 0, fileContent.length);

    //             if (decryptedHash.equals(new BigInteger(1, tmpHash.digest()))) {
    //                 Printer.success("The file has not been modified, the signature is correct.");
    //                 flag = true;
    //                 break;
    //             }
    //         }
    //         if (!flag)
    //             Printer.warning("The contents of the file have been changed");
    //     } catch (Exception e) {
    //         e.printStackTrace();
    //     }
    // }
}