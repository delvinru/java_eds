package com.delvin;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import com.delvin.cipher.RSA;
import com.delvin.printer.Printer;

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
            RSA rsa = new RSA(hash, keySize, inFile, outFile, verbose);
            rsa.encrypt();
        } catch (NoSuchAlgorithmException e) {
            Printer.error(e.toString());
            System.exit(1);
        } catch (IOException e) {
            Printer.error(e.toString());
            System.exit(1);
        }
    }

    public void checkSign() {

    }
}
