package com.delvin.hash;

public class MessageDigest {
    public static Hash getInstance(String hashType) throws NoImplementedAlgorithmException {
        if (hashType.equals("SHA-1"))
            return new SHA1();
        else
            throw new NoImplementedAlgorithmException("Algorithm: " + hashType + " not implemented!");
    }
}