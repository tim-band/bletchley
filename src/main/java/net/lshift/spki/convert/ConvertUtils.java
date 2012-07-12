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

import net.lshift.spki.AdvancedSpkiInputStream;
import net.lshift.spki.CanonicalSpkiInputStream;
import net.lshift.spki.CanonicalSpkiOutputStream;
import net.lshift.spki.Constants;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.SpkiInputStream;
import net.lshift.spki.SpkiInputStream.TokenType;
import net.lshift.spki.SpkiOutputStream;
import net.lshift.spki.sexpform.ConvertSexp;

/**
 * Static utilities for conversion between SExps and objects.
 */
public class ConvertUtils {
    public static byte[] bytes(final String s) {
        return s.getBytes(Constants.UTF8);
    }

    public static final String decodeUtf8(final byte[] bytes)
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

    // FIXME: what about EOF?
    public static <T extends Writeable> void write(
        final T o,
        final SpkiOutputStream os) throws IOException {
        ConvertSexp.write(os, o.toSexp());
    }

    public static void write(
        final Writeable o,
        final OutputStream os)
        throws IOException {
        write(o, new CanonicalSpkiOutputStream(os));
    }

    public static void write(
        final Writeable o,
        final File f)
        throws IOException {
        final FileOutputStream os = new FileOutputStream(f);
        try {
            write(o, os);
        } finally {
            os.close();
        }
    }

    public static <T> T read(
        final ReadInfo r,
        final Class<T> clazz, final SpkiInputStream is)
        throws IOException, InvalidInputException {
        final T res = r.read(clazz, ConvertSexp.read(is));
        if (is.next() != TokenType.EOF) {
            throw new ConvertException("File continues after object read");
        }
        return res;
    }

    public static <T> T read(
        final ReadInfo r,
        final Class<T> clazz, final InputStream is)
        throws IOException, InvalidInputException {
        return read(r, clazz, new CanonicalSpkiInputStream(is));
    }

    public static <T> T read(
        final ReadInfo r,
        final Class<T> clazz, final File f)
        throws IOException,
            InvalidInputException {
        final FileInputStream is = new FileInputStream(f);
        try {
            return read(r, clazz, is);
        } finally {
            is.close();
        }
    }

    /**
     * WARNING: this closes the stream passed in!
     */
    public static <T> T readAdvanced(
        final ReadInfo r,
        final Class<T> clazz, final InputStream is)
        throws IOException, InvalidInputException {
        return read(r, clazz, new AdvancedSpkiInputStream(is));
    }

    public static byte[] toBytes(
        final Writeable o) {
        try {
            final ByteArrayOutputStream os = new ByteArrayOutputStream();
            write(o, os);
            os.close();
            return os.toByteArray();
        } catch (final IOException e) {
            throw new RuntimeException(
                "ByteArrayInputStream cannot throw IOException", e);
        }
    }

    public static <T> T fromBytes(
        final ReadInfo r,
        final Class<T> clazz, final byte[] bytes)
        throws InvalidInputException {
        try {
            return read(r, clazz, new ByteArrayInputStream(bytes));
        } catch (final IOException e) {
            throw new RuntimeException(
                "ByteArrayInputStream cannot throw IOException", e);
        }
    }

    public static void prettyPrint(
        final Writeable o,
        final PrintWriter ps)
        throws IOException {
        write(o, new PrettyPrinter(ps));
    }

    public static String prettyPrint(final Writeable o) {
        final StringWriter writer = new StringWriter();
        try {
            final PrintWriter pw = new PrintWriter(writer);
            prettyPrint(o, pw);
            pw.close();
        } catch (final IOException e) {
            // should not be possible
            throw new RuntimeException(e);
        }
        return writer.toString();
    }

    public static void prettyPrint(
        final Writeable o,
        final OutputStream out) throws IOException {
        final PrintWriter ps = new PrintWriter(out);
        prettyPrint(o, ps);
        ps.flush();
    }
}
