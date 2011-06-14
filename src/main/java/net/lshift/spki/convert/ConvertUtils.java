package net.lshift.spki.convert;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;

import net.lshift.spki.Constants;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.SpkiInputStream.TokenType;

/**
 * Static utilities for conversion between SExps and objects.
 */
public class ConvertUtils {
    private static final CharsetDecoder UTF8_DECODER
        = Constants.UTF8.newDecoder();

    public static byte[] bytes(final String s) {
        return s.getBytes(Constants.UTF8);
    }

    public static String string(final byte[] bytes) throws ParseException {
        try {
            return UTF8_DECODER.decode(ByteBuffer.wrap(bytes)).toString();
        } catch (final CharacterCodingException e) {
            throw new ParseException("Cannot convert bytes to string", e);
        }
    }

    // Useful for comparison
    public static String stringOrNull(final byte[] bytes) {
        try {
            return UTF8_DECODER.decode(ByteBuffer.wrap(bytes)).toString();
        } catch (final CharacterCodingException e) {
            return null;
        }
    }

    public static <T> void initialize(final Class<T> clazz)
        throws AssertionError {
        // Ensure the class is initialized
        // in case it statically registers converters
        // http://java.sun.com/j2se/1.5.0/compatibility.html
        try {
            Class.forName(clazz.getName(), true, clazz.getClassLoader());
        } catch (final ClassNotFoundException e) {
            throw new ConvertReflectionException(clazz, e);  // Can't happen
        }
    }

    public static <T> void write(final Class<T> clazz, final T o, final OutputStream os)
        throws IOException {
        final ConvertOutputStream out = new ConvertOutputStream(os);
        out.write(clazz, o);
        out.close();
    }

    public static <T> T read(final Class<T> clazz, final InputStream is)
        throws IOException, InvalidInputException {
        try {
            final ConvertInputStream in
                = new ConvertInputStream(is);
            final T res = in.read(clazz);
            in.nextAssertType(TokenType.EOF);
            return res;
        } finally {
            is.close();
        }
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

    public static <T> void prettyPrint(final Class<T> clazz, final T o, final PrintStream ps)
        throws IOException {
        final ConvertOutputStream out
            = new ConvertOutputStream(new PrettyPrinter(ps));
        out.write(clazz, o);
        out.close();
    }
}
