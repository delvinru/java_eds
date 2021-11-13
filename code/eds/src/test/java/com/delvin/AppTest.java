package com.delvin;

import static org.junit.Assert.*;

import com.delvin.hash.SHA1;

import org.junit.Test;

public class AppTest {
    @Test
    public void testSHA1_1() {
        SHA1 hash = new SHA1();
        String test = "The quick brown fox jumps over the lazy dog";
        byte[] arr = test.getBytes();
        String res = hash.hexdigest(arr);
        assertEquals("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", res);
    }

    @Test
    public void testSHA1_2() {
        SHA1 hash = new SHA1();
        String test = "sha";
        byte[] arr = test.getBytes();
        String res = hash.hexdigest(arr);
        assertEquals("d8f4590320e1343a915b6394170650a8f35d6926", res);
    }

    @Test
    public void testSHA1_3() {
        SHA1 hash = new SHA1();
        String test = "привет";
        byte[] arr = test.getBytes();
        String res = hash.hexdigest(arr);
        assertEquals("e24505f94db2b5df4c7c2596b0788e720e073021", res);
    }

    @Test
    public void testSHA1_4() {
        SHA1 hash = new SHA1();
        byte[] arr = { 0x10, 0x20, 0x30, 0x40, 0x50 };
        String res = hash.hexdigest(arr);
        assertEquals("7094fad0098792d6dfa0fc27c99181d23de02bd3", res);
    }

    @Test
    public void testSHA1_5() {
        SHA1 hash = new SHA1();
        String test = "В чащах юга жил бы цитрус? Да, но фальшивый экземпляр!";
        String res = hash.hexdigest(test.getBytes());
        assertEquals("9e32295f8225803bb6d5fdfcc0674616a4413c1b", res);
    }

    @Test
    public void testSHA1_6() {
        SHA1 hash = new SHA1();
        StringBuilder test = new StringBuilder();
        for (int i = 0; i < 0x31337; i++)
            test.append('A');
        String res = hash.hexdigest(test.toString().getBytes());
        assertEquals("a2790d0a4e1b0389ac26119577a491e697151dd7", res);
    }
}
