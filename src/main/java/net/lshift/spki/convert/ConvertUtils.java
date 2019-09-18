package net.lshift.spki.convert;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;

import com.google.protobuf.DiscardUnknownFieldsParser;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import com.google.protobuf.util.JsonFormat;
import com.google.protobuf.util.JsonFormat.Parser;
import com.google.protobuf.util.JsonFormat.Printer;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.bletchley.suiteb.proto.SuiteBProto.SequenceItem.Builder;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.suiteb.SequenceItem;
import net.lshift.spki.suiteb.SequenceItemConverter;

/**
 * Static utilities for conversion between SExps and objects.
 */
public class ConvertUtils {
	
    private ConvertUtils() {
        // This class cannot be instantiated
    }
	
    public static byte[] bytes(final String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    public static final String decodeUtf8(final byte[] bytes)
        throws CharacterCodingException {
        return StandardCharsets.UTF_8.newDecoder()
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

    public static void write(final SequenceItem item, final OutputStream os) throws IOException {
        item.toProtobuf().build().writeTo(os);
    }

    public static void write(final SequenceItem item, final File f) throws IOException {        
        try(FileOutputStream os = new FileOutputStream(f)) {
            write(item, os);
        }
    }

    @SafeVarargs
    public static SequenceItem read(final InputStream is, Class<? extends Message> ... actionTypes)
            throws IOException, InvalidInputException {
        try {
            return new SequenceItemConverter(actionTypes).fromProtobuf(parse(is));
        } catch(InvalidProtocolBufferException e) {
            throw new InvalidInputException(e); 
        }
    }

    private static net.lshift.bletchley.suiteb.proto.SuiteBProto.SequenceItem parse(
            final InputStream is) throws InvalidProtocolBufferException {
        return DiscardUnknownFieldsParser.wrap(SuiteBProto.SequenceItem.parser()).parseFrom(is);
    }

    @SafeVarargs
    public static SequenceItem readAdvanced(final InputStream is, Class<? extends Message> ... actionTypes)
            throws IOException, InvalidInputException {
        Builder builder = SuiteBProto.SequenceItem.newBuilder();
        parser().merge(new InputStreamReader(is), builder);
        return new SequenceItemConverter(actionTypes).fromProtobuf(builder.build());
    }

    public static byte[] toBytes(final SequenceItem item) {
        try {
            final ByteArrayOutputStream os = new ByteArrayOutputStream();
            write(item, os);
            os.close();
            return os.toByteArray();
        } catch (final IOException e) {
            throw new AssertionError(
                "ByteArrayInputStream cannot throw IOException", e);
        }
    }

    public static void prettyPrint(
            final SequenceItem item,
            final PrintWriter ps) throws InvalidProtocolBufferException {
        ps.print(printer().print(item.toProtobuf()));
    }

    public static String prettyPrint(final SequenceItem item) throws InvalidInputException {
        try {
            return printer().print(item.toProtobuf());
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidInputException("Error printing JSON for SequenceItem", e);
        }
    }

    public static void prettyPrint(
            final SequenceItem item,
            final OutputStream out) throws IOException {
        final PrintWriter ps = new PrintWriter(out);
        prettyPrint(item, ps);
        ps.flush();
    }

    private static Printer printer() {
        return JsonFormat.printer();
    }

    private static Parser parser() {
        return JsonFormat.parser();
    }
}
