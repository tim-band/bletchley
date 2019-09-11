package net.lshift.spki.convert.openable;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.text.MessageFormat;
import java.util.Optional;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ConvertReflectionException;
import net.lshift.spki.convert.ProtobufConvert;
import net.lshift.spki.suiteb.SequenceItem;

import org.apache.commons.io.IOUtils;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;

/**
 * Utilities for acting on Openable objects
 */
public class OpenableUtils {
    private OpenableUtils() {
        // This class cannot be instantiated
    }

    public static byte[] readBytes(final Openable message) throws IOException {
        final InputStream is = message.read();
        try {
            return IOUtils.toByteArray(is);
        } finally {
            is.close();
        }
    }

    public static void writeBytes(final Openable out, final byte[] messageBytes)
            throws IOException {
        final OutputStream os = out.write();
        try {
            os.write(messageBytes);
        } finally {
            os.close();
        }
    }

    /**
     * Read a file containing a SuiteB object wrapped in Any. Generally, the
     * command line tools write files containing objects wrapped in {@link Any}.
     * Some objects like PrivateSigningKey are not part of the wire protocol,
     * and can only be read and written this way. To read and write the wire
     * protocol (where all messages are SequenceItem) use
     * {@link #read(Class, Openable)}
     * 
     * @param clazz
     *            the expected type of the object
     * @param open
     *            the openable to read from
     * @return the object read
     * @throws IOException
     * @throws InvalidInputException
     *             if the type is not as expected, or the message otherwise
     *             doesn't satisfy the type
     */
    @SuppressWarnings("unchecked")
    public static <B extends Message.Builder, U extends ProtobufConvert<B>> U readAny(
            final Class<U> clazz, final Openable open)
            throws IOException, InvalidInputException {
        final InputStream is = open.read();
        try {
            Any any = Any.parseFrom(open.read());
            Class<Message> pbclass = (Class<Message>)Optional.ofNullable(
                clazz.getAnnotation(ProtobufConvert.ProtobufClass.class))
                    .map(a -> a.value())
                    .orElseThrow(() -> new IllegalArgumentException(
                            MessageFormat.format("{0} does not have annotation {1}", 
                                    clazz, ProtobufConvert.ProtobufClass.class)) );
            return (U) clazz.getMethod("fromProtobuf", pbclass).invoke(null,
                    any.unpack(pbclass));
        } catch (IllegalAccessException | IllegalArgumentException
                | InvocationTargetException | NoSuchMethodException
                | SecurityException e) {
            throw new ConvertReflectionException(clazz, e);
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidInputException(e);
        } finally {
            is.close();
        }
    }

    public static <B extends Message.Builder> void writeAny(final Openable open,
            final ProtobufConvert<B> message) throws IOException {
        final OutputStream os = open.write();
        try {
            Any.pack(message.toProtobuf().build()).writeTo(os);
        } finally {
            os.close();
        }
    }

    @SuppressWarnings("unchecked")
    public static <T extends SequenceItem> T read(final Class<T> clazz,
            final Openable open) throws IOException, InvalidInputException {
        final InputStream is = open.read();
        try {
            SequenceItem sequenceItem = SequenceItem.fromProtobuf(
                    SuiteBProto.SequenceItem.parseFrom(open.read()));
            if (clazz.isInstance(sequenceItem)) {
                return (T) sequenceItem;
            } else {
                throw new InvalidInputException(
                        MessageFormat.format("Expected {0} item type {1}",
                                clazz, sequenceItem.getClass()));
            }
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidInputException(e);
        } finally {
            is.close();
        }
    }

    public static void write(final Openable open, final SequenceItem item)
            throws IOException {
        final OutputStream os = open.write();
        try {
            item.toProtobuf().build().writeTo(os);
        } finally {
            os.close();
        }
    }

    public static void writeBytes(Openable out, ByteString content)
            throws IOException {
        writeBytes(out, content.toByteArray());
    }

}
