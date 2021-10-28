package com.delvin.cipher;

import java.io.IOException;

public interface Cipher {
    void encrypt() throws IOException;
    void decrypt() throws IOException;
}
