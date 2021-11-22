package com.delvin.hash;

public class SHA1 implements Hash {
    private int h0 = 0x67452301;
    private int h1 = 0xEFCDAB89;
    private int h2 = 0x98BADCFE;
    private int h3 = 0x10325476;
    private int h4 = 0xC3D2E1F0;

    /**
     * @param content data to hash
     * @return the SHA-1 hashsum in byte array
     */
    public byte[] digest(byte[] content) {
        // Create array that will store 16-word blocks
        int[] blocks = new int[(((content.length + 8) >> 6) + 1) * 16];

        // Create from bytes to integer using bitshift and or mask
        // 0,1,2,3 >> 2 == 0
        // content[0] = 0x11
        // content[1] = 0x22
        // content[2] = 0x33
        // content[3] = 0x44
        // i == 1: 0x11000000
        // i == 2: 0x11220000
        // i == 3: 0x11223300
        // i == 4: 0x11223344
        for (int i = 0; i < content.length; i++)
            blocks[i >> 2] |= (content[i] & 0xff) << (24 - (i % 4) * 8);

        // Append padding bits like in specification
        // 0x80 == 0b10000000
        blocks[content.length >> 2] |= 0x80 << (24 - (content.length % 4) * 8);
        // Last block contains size of content
        blocks[blocks.length - 1] = content.length * 8;

        // SHA1 algorithm
        int[] w = new int[80];
        for (int i = 0; i < blocks.length; i += 16) {
            int a = h0;
            int b = h1;
            int c = h2;
            int d = h3;
            int e = h4;

            for (int j = 0; j < 80; j++) {
                if (j < 16)
                    w[j] = blocks[i + j];
                else
                    w[j] = rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);

                int f;
                int k;
                if (j < 20) {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999;
                } else if (j < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if (j < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }
                int tmp = rol(a, 5) + f + e + k + w[j];
                e = d;
                d = c;
                c = rol(b, 30);
                b = a;
                a = tmp;
            }
            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
        }

        byte[] digest = new byte[20];
        int2b(h0, digest, 0);
        int2b(h1, digest, 4);
        int2b(h2, digest, 8);
        int2b(h3, digest, 12);
        int2b(h4, digest, 16);
        return digest;
    }

    private void int2b(int value, byte[] arr, int off) {
        arr[off + 0] = (byte) ((value >> 24) & 0xff);
        arr[off + 1] = (byte) ((value >> 16) & 0xff);
        arr[off + 2] = (byte) ((value >> 8) & 0xff);
        arr[off + 3] = (byte) ((value >> 0) & 0xff);
    }

    /**
     * @param content data to hash
     * @return the SHA-1 hashsum in hexdigest string
     */
    public String hexdigest(byte[] content) {
        byte[] res = this.digest(content);
        StringBuilder builder = new StringBuilder();
        for (byte b : res)
            builder.append(String.format("%02x", b));
        return builder.toString();
    }

    // Bitwise rotate 32 bit to the left
    private int rol(int num, int cnt) {
        return (num << cnt) | (num >>> (32 - cnt));
    }
}