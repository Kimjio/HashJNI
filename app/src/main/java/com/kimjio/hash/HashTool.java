package com.kimjio.hash;

import android.util.Base64;

import java.nio.ByteBuffer;

public final class HashTool {
    static {
        System.loadLibrary("hash");
    }

    public static String getHash(String idToken, String timestamp) {
        int[] hash = getHashBytes(idToken, timestamp);
        ByteBuffer buffer = ByteBuffer.allocate(20);
        for (int i = 0; i < 5; i++) {
            buffer.putInt(hash[i]);
        }
        return Base64.encodeToString(buffer.array(), Base64.DEFAULT).trim();
    }

    private static String getString(int[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (int b : bytes) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

    public static native int[] getHashBytes(String idToken, String timestamp);
}
