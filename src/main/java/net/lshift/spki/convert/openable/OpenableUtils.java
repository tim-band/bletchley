package net.lshift.spki.convert.openable;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ConvertUtils;

import org.apache.commons.io.IOUtils;

/**
 * Utilities for acting on Openable objects
 */
public class OpenableUtils {
    public static byte[] readBytes(final Openable message)
        throws IOException {
        final InputStream is = message.read();
        try {
            return IOUtils.toByteArray(is);
        } finally {
            is.close();
        }
    }

    public static void writeBytes(final byte[] messageBytes, final Openable out)
        throws IOException {
        final OutputStream os = out.write();
        try {
            os.write(messageBytes);
        } finally {
            os.close();
        }
    }

    public static <T> T read(final Class<T> clazz, final Openable open)
        throws IOException, InvalidInputException {
        final InputStream is = open.read();
        try {
            return ConvertUtils.read(clazz, is);
        } finally {
            is.close();
        }
    }

    public static <T> void write(final Class<T> clazz, final T o, final Openable open)
        throws IOException {
        final OutputStream os = open.write();
        try {
            ConvertUtils.write(clazz, o, os);
        } finally {
            os.close();
        }
    }
}
