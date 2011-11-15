package net.lshift.spki.convert;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;

import net.lshift.spki.Constants;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.SpkiInputStream.TokenType;

/**
 * Static utilities for conversion between SExps and objects.
 */
public class ConvertUtils {
    public static byte[] bytes(final String s) {
        return s.getBytes(Constants.UTF8);
    }

    private static final String decodeUtf8(final byte[] bytes)
        throws CharacterCodingException {
        return Constants.UTF8.newDecoder()
            .decode(ByteBuffer.wrap(bytes)).toString();
    }

    public static String string(final byte[] bytes) throws ConvertException {
        try {
            return decodeUtf8(bytes);
        } catch (final CharacterCodingException e) {
            throw new ConvertException("Cannot convert bytes to string", e);
        }
    }

    // Useful for comparison
    public static String stringOrNull(final byte[] bytes) {
        try {
            return decodeUtf8(bytes);
        } catch (final CharacterCodingException e) {
            return null;
        }
    }

    /**
     * WARNING: this closes the stream passed in!
     */
    public static <T> void write(final Class<T> clazz, final T o, final OutputStream os)
        throws IOException {
        final ConvertOutputStream out = new ConvertOutputStream(os);
        try {
            out.write(clazz, o);
        } finally {
            out.close();
        }
    }

    public static <T> void write(final Class<T> clazz, final T o, final File f)
        throws IOException {
        write(clazz, o, new FileOutputStream(f));
    }

    /**
     * WARNING: this closes the stream passed in!
     */
    public static <T> T read(final Class<T> clazz, final InputStream is)
        throws IOException, InvalidInputException {
        try {
            final ConvertInputStream in = new ConvertInputStream(is);
            final T res = in.read(clazz);
            in.nextAssertType(TokenType.EOF);
            return res;
        } finally {
            is.close();
        }
    }

    public static <T> T read(final Class<T> clazz, final File f)
        throws IOException,
            InvalidInputException {
        return read(clazz, new FileInputStream(f));
    }

    public static <T> byte[] toBytes(final Class<T> clazz, final T o) {
        try {
            final ByteArrayOutputStream os = new ByteArrayOutputStream();
            write(clazz, o, os);
            return os.toByteArray();
        } catch (final IOException e) {
            throw new ConvertReflectionException(clazz,
                "ByteArrayOutputStream cannot throw IOException", e);
        }
    }

    public static <T> T fromBytes(final Class<T> clazz, final byte[] bytes)
        throws InvalidInputException {
        try {
            return read(clazz, new ByteArrayInputStream(bytes));
        } catch (final IOException e) {
            throw new ConvertReflectionException(clazz,
                "ByteArrayInputStream cannot throw IOException", e);
        }
    }

    public static <T> void prettyPrint(
        final Class<T> clazz,
        final T o,
        final PrintWriter ps)
        throws IOException {
        final ConvertOutputStream out
            = new ConvertOutputStream(new PrettyPrinter(ps));
        out.write(clazz, o);
        out.close();
    }

    public static <T> String prettyPrint(final Class<T> clazz, final T o) {
        StringWriter writer = new StringWriter();
        try {
            final PrintWriter pw = new PrintWriter(writer);
            prettyPrint(clazz, o, pw);
            pw.close();
        } catch (final IOException e) {
            // should not be possible
            throw new RuntimeException(e);
        }
        return writer.toString();
    }

    public static <T> void prettyPrint(
        Class<T> clazz,
        T o,
        OutputStream out) throws IOException {
        final PrintWriter ps = new PrintWriter(out);
        prettyPrint(clazz, o, ps);
        ps.flush();
    }
}
