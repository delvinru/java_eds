package com.delvin;

import com.beust.jcommander.Parameter;
import com.delvin.printer.Printer;

class Args {
    @Parameter(names = { "-h", "--help" }, description = "Show this help menu and exit")
    private boolean help = false;

    @Parameter(names = { "-m", "--mode" }, description = "Available modes: sign, check")
    private String mode = "sign";
    private String[] modes = { "sign", "check" };

    @Parameter(names = { "-f", "--file" }, description = "The file to be signed")
    private String inFile;

    @Parameter(names = { "-o", "--out" }, description = "Output file name")
    private String outFile;

    @Parameter(names = { "-b", "--bytes" }, description = "The size of the key used to generate the EDS")
    private Integer keySize = 4096;

    @Parameter(names = { "-a", "--algorithm" }, description = "Choose an hash for sign: SHA-1")
    private String algorithm = "SHA-1";
    private String[] availableHashes = { "SHA-1" };

    @Parameter(names = { "-g", "--generate" }, description = "Generate a public/private key pair")
    private boolean generate = false;

    @Parameter(names = { "-pub", "--public" }, description = "A file with a public key.")
    private String publicKeyFile;

    @Parameter(names = { "-prv", "--private" }, description = "A file with a private key.")
    private String privateKeyFile;

    @Parameter(names = { "-v", "--verbose" }, description = "Verbose logs in console")
    private boolean verbose = false;

    public boolean isHelp() {
        return this.help;
    }

    public String getMode() {
        for (String m : this.modes)
            if (m.equals(this.mode))
                return this.mode;
        return "none";
    }

    public String getFileName() {
        return this.inFile;
    }

    public String getOutFileName() {
        if (this.outFile == null || this.outFile.isEmpty())
            return this.inFile + ".sig";
        return this.outFile;
    }

    public Integer getKeySize() {
        return this.keySize;
    }

    public String getAlgorithm() {
        for (String algo : this.availableHashes)
            if (algo.equals(this.algorithm.toUpperCase()))
                return this.algorithm;
        return "none";
    }

    public String[] getAllHashes() {
        return this.availableHashes;
    }

    public boolean getVerbose() {
        return this.verbose;
    }

    public boolean getGenerateKey() {
        return this.generate;
    }

    public String getPublicKeyFile() {
        if (this.publicKeyFile == null || this.publicKeyFile.isEmpty())
            return "key.pub";
        return this.publicKeyFile;
    }

    public boolean checkPublicKeyFile() {
        if (this.publicKeyFile == null || this.publicKeyFile.isEmpty())
            return false;
        return true;
    }

    public String getPrivateKeyFile() {
        if (this.privateKeyFile == null || this.privateKeyFile.isEmpty())
            return "key.prv";
        return this.privateKeyFile;
    }

    public boolean checkPrivateKeyFile() {
        if (this.privateKeyFile == null || this.privateKeyFile.isEmpty())
            return false;
        return true;
    }

    public boolean getGenerateFlag() {
        return this.generate;
    }

    public String incorrectHash() {
        return "Incorrect algorithm, choose one of the presented: " + String.join(", ", this.availableHashes);
    }

    public String incorrectMode() {
        return "Incorrect mode, choose one of the presented: " + String.join(", ", this.modes);
    }

    public String incorrectKeySize() {
        return "The key size must be greater than 2048 bits and be a power of two.";
    }

    public boolean checkKeySize() {
        if (this.keySize >= 8192)
            Printer.warning("This may take some time, since the key size is large.");

        if (this.keySize < 2048 || this.keySize % 2 != 0)
            return false;
        return true;
    }

    public boolean checkFileName() {
        if (this.inFile == null || this.inFile.isEmpty())
            return false;
        return true;
    }
}