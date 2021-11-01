package com.delvin.cipher;

public interface Key {
    public byte[] dumpKey();
    public void readKey(byte[] content);    
}
