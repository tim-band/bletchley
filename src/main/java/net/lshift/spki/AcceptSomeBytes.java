package net.lshift.spki;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Simple class to pull only bytes matching some criteria from an InputStream
 * and push them to the OutputStream.
 */
public class AcceptSomeBytes {
    public static final AcceptSomeBytes PRINTABLES = getPrintables();
    public static final AcceptSomeBytes STRING = getString();
    public static final AcceptSomeBytes HEX = getHex();
    public static final AcceptSomeBytes BASE64 = getBase64();
    public static final AcceptSomeBytes TOKEN = getToken();

    private final byte[] accept = new byte[256];

    // make the constructor private so only we can do things to it
    private AcceptSomeBytes() {
        for (int i = 0; i < 256; i++)
            accept[i] = 0;
    }

    public int accept(final OutputStream out, final InputStream is) throws IOException {
        while (true) {
            final int b = is.read();
            if (b == -1 || accept[b] == 0) {
                return b;
            }
            out.write(b);
        }
    }

    private static AcceptSomeBytes getPrintables() {
        final AcceptSomeBytes res = new AcceptSomeBytes();
        for (int i = 0x20; i < 0x7E; i++)
            res.accept[i] = 1;
        return res;
    }

    private static AcceptSomeBytes getString() {
        final AcceptSomeBytes res = getPrintables();
        res.accept['"'] = 0;
        res.accept['\\'] = 0;
        return res;
    }

    private static AcceptSomeBytes getHex() {
        final AcceptSomeBytes res = new AcceptSomeBytes();
        for (final int c: "0123456789abcdefABCDEF\n\r\t ".toCharArray()) {
            res.accept[c] = 1;
        }
        return res;
    }

    private static AcceptSomeBytes getAlnum() {
        final AcceptSomeBytes res = new AcceptSomeBytes();
        for (int c = 'A'; c <= 'Z'; c++) res.accept[c] = 1;
        for (int c = 'a'; c <= 'z'; c++) res.accept[c] = 1;
        for (int c = '0'; c <= '9'; c++) res.accept[c] = 1;
        return res;
    }

    // I would like to add white space characters here,
    // but BouncyCastle's white space skipping is broken
    private static AcceptSomeBytes getBase64() {
        final AcceptSomeBytes res = getAlnum();
        res.accept['+'] = 1;
        res.accept['/'] = 1;
        res.accept['='] = 1;
        return res;
    }

    private static AcceptSomeBytes getToken() {
        final AcceptSomeBytes res = getAlnum();
        res.accept['-'] = 1;
        return res;
    }
}
