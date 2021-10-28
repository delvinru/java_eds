package com.delvin;

import com.beust.jcommander.Parameter;

class Args {
    @Parameter(names = { "-h", "--help" }, description = "Show this help menu and exit")
    private boolean help = false;

    @Parameter(names = { "-m", "--mode" }, description = "Available modes: sign, check")
    private String mode = "sign";
    private String[] modes = { "sign", "check" };

    @Parameter(names = { "-f", "--file" }, description = "The file to be signed", required = true)
    private String inFile = "none";

    @Parameter(names = { "-o", "--out" }, description = "Output file name")
    private String outFile = inFile + ".sig";

    @Parameter(names = { "-b", "--bytes" }, description = "The size of the key used to generate the EDS")
    private Integer keySize = 4096;

    @Parameter(names = { "-a", "--algorithm" }, description = "Choose an hash for sign: MD5, SHA-1, SHA-256, SHA-512")
    private String algorithm = "SHA-256";
    private String[] availableHashes = { "MD5", "SHA-1", "SHA-256", "SHA-512" };

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
        return this.outFile;
    }

    public Integer getKeySize() {
        return this.keySize;
    }

    public String getAlgorithm() {
        for (String algo : this.availableHashes)
            if (algo.equals(this.algorithm))
                return this.algorithm;
        return "none";
    }

    public boolean getVerbose() {
        return this.verbose;
    }
}