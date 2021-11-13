package com.delvin.hash;

public interface Hash {
    byte[] digest(byte[] content);

    String hexdigest(byte[] content);
}
