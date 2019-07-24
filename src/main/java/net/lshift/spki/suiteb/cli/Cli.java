package net.lshift.spki.suiteb.cli;

import static net.lshift.spki.convert.openable.OpenableUtils.write;
import static net.lshift.spki.convert.openable.OpenableUtils.writeAny;
import static net.lshift.spki.suiteb.Signed.signed;
import static net.lshift.spki.suiteb.fingerprint.FingerprintUtils.getFingerprint;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.protobuf.ByteString;

import net.lshift.bletchley.suiteb.proto.PrivateSigningKeyProto;
import net.lshift.bletchley.suiteb.proto.SimpleMessageProto.SimpleMessage;
import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.AdvancedSpkiInputStream;
import net.lshift.spki.CanonicalSpkiOutputStream;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.convert.openable.FileOpenable;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.convert.openable.OpenableUtils;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.EncryptionCache;
import net.lshift.spki.suiteb.InferenceEngine;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.PublicSigningKey;
import net.lshift.spki.suiteb.Sequence;
import net.lshift.spki.suiteb.SequenceItem;
import net.lshift.spki.suiteb.SequenceUtils;

/**
 * Command line interface to crypto functions
 */
public class Cli {
	private static final Logger log = LoggerFactory.getLogger(Cli.class);

    private static final String CLI_MESSAGE = Cli.class.toString();

    private static <U extends SequenceItem> U read(final Class<U> clazz, final Openable open)
        throws IOException, InvalidInputException {
        return OpenableUtils.read(clazz, open);
    }

    private static PrivateSigningKey readPrivateSigningKey(Openable keyFile) 
            throws IOException, InvalidInputException {
        return OpenableUtils.readAny(PrivateSigningKey.class, keyFile);
    }

    private static SequenceItem read(final Openable open)
        throws IOException, InvalidInputException {
        return read(SequenceItem.class, open);
    }

    public static void prettyPrint(final Openable file, PrintStream stdout)
        throws IOException,
            ParseException {
        PrettyPrinter.prettyPrint(new PrintWriter(stdout), file.read());
    }

    public static void prettyPrintToFile(final Openable in, final Openable out)
                    throws ParseException, IOException {
        final PrintWriter pw = new PrintWriter(out.write());
        PrettyPrinter.prettyPrint(pw, in.read());
        pw.close();
    }

    public static void canonical(final Openable in, final Openable out) throws IOException, ParseException {
        PrettyPrinter.copyStream(
            new AdvancedSpkiInputStream(in.read()),
            new CanonicalSpkiOutputStream(out.write()));
    }

    public static void genSigningKey(final Openable out)
        throws IOException {
        writeAny(out, PrivateSigningKey.generate());
    }

    public static void genEncryptionKey(final Openable out)
        throws IOException {
        writeAny(out, PrivateEncryptionKey.generate());
    }

    public static void getPublicSigningKey(final Openable privk, final Openable pubk)
        throws IOException, InvalidInputException {
        final PrivateSigningKey privatek = readPrivateSigningKey(privk);
        writeAny(pubk, privatek.getPublicKey());
    }

    public static void getPublicEncryptionKey(final Openable privk, final Openable pubk)
        throws IOException, InvalidInputException {
        final PrivateEncryptionKey privatek
            = read(PrivateEncryptionKey.class, privk);
        writeAny(pubk, privatek.getPublicKey());
    }

    public static void fingerprintPrivateSigningKey(
        final PrintStream stdout,
        final Openable privk) throws IOException, InvalidInputException {
        stdout.println(getFingerprint(
            readPrivateSigningKey(privk).getPublicKey().getKeyId()));
    }

    public static void fingerprintPublicSigningKey(
        final PrintStream stdout,
        final Openable pubk) throws IOException, InvalidInputException {
        stdout.println(getFingerprint(
            OpenableUtils.readAny(PublicSigningKey.class, pubk).getKeyId()));
    }

    public static void fingerprintPrivateEncryptionKey(
        final PrintStream stdout,
        final Openable privk) throws IOException, InvalidInputException {
        stdout.println(getFingerprint(
            read(PrivateEncryptionKey.class, privk).getPublicKey().getKeyId()));
    }

    public static void fingerprintPublicEncryptionKey(
        final PrintStream stdout,
        final Openable pubk) throws IOException, InvalidInputException {
        stdout.println(getFingerprint(
            read(PublicEncryptionKey.class, pubk).getKeyId()));
    }

    public static void decryptSignedMessage(
        final String messageType,
        final PrivateEncryptionKey encryptionKey,
        final PublicSigningKey signingKey,
        final Openable packet,
        final Openable out)
        throws IOException, InvalidInputException {
        final InferenceEngine<SimpleMessage> inference = new InferenceEngine<>(SimpleMessage.class);
        inference.processTrusted(signingKey);
        inference.process(encryptionKey);
        inference.process(read(packet));
        final SimpleMessage message
            = inference.getSoleAction(SimpleMessage.class);
        if (!messageType.equals(message.getType())) {
            throw new IllegalArgumentException("Message was not of expected type");
        }
        OpenableUtils.writeBytes(out, message.getContent());
    }

    public static void decryptSignedMessage(
        final String messageType,
        final Openable ePrivate,
        final Openable sPublic,
        final Openable packet,
        final Openable out)
        throws IOException, InvalidInputException {
        final PrivateEncryptionKey encryptionKey
            = read(PrivateEncryptionKey.class, ePrivate);
        final PublicSigningKey signingKey = read(PublicSigningKey.class, sPublic);
        decryptSignedMessage(messageType, encryptionKey, signingKey, packet, out);
    }

    public static void genEncryptedSignedMessage(
        final String messageType,
        final Openable[] args)
        throws IOException, InvalidInputException {
        final List<SequenceItem> sequenceItems = new ArrayList<>();
        final AesKey aesKey = AesKey.generateAESKey();
        final EncryptionCache ephemeral = EncryptionCache.ephemeralKey();
        sequenceItems.add(ephemeral.getPublicKey());
        for (int i = 2; i < args.length - 1; i++) {
            final PublicEncryptionKey pKey
                = read(PublicEncryptionKey.class, args[i]);
            sequenceItems.add(ephemeral.encrypt(pKey, aesKey));
        }

        final List<SequenceItem> encryptedSequenceItems = new ArrayList<>();
        final Action message = SequenceUtils.action(SimpleMessage.newBuilder()
                .setType(messageType)
                .setContent(ByteString.copyFrom(OpenableUtils.readBytes(args[1])))
                .build());
        final PrivateSigningKey privateKey
            = readPrivateSigningKey(args[0]);
        encryptedSequenceItems.add(privateKey.sign(message));
        encryptedSequenceItems.add(signed(message));

        sequenceItems.add(aesKey.encrypt(new Sequence(encryptedSequenceItems)));

        // Almost everything we write from the command line is wrapped in an
        // 'any'. This is an exception: so that, for example, you could send
        // the resulting file to a message queue. I.e. here, we are using the
        // wire encoding.
        write(args[args.length - 1], new Sequence(sequenceItems));
    }

    public static void speedTest() throws InvalidInputException {
        new SpeedTester().speedTest();
    }

    public static void main(
        final PrintStream stdout,
        final String command,
        final Openable... args)
        throws IOException, InvalidInputException {
        if ("prettyPrint".equals(command)) {
            prettyPrint(args[0], stdout);
        } else if ("prettyPrintToFile".equals(command)) {
            prettyPrintToFile(args[0], args[1]);
        } else if ("canonical".equals(command)) {
            canonical(args[0], args[1]);
        } else if ("genSigningKey".equals(command)) {
            genSigningKey(args[0]);
        } else if ("genEncryptionKey".equals(command)) {
            genEncryptionKey(args[0]);
        } else if ("getPublicSigningKey".equals(command)) {
            getPublicSigningKey(args[0], args[1]);
        } else if ("getPublicEncryptionKey".equals(command)) {
            getPublicEncryptionKey(args[0], args[1]);
        } else if ("fingerprintPrivateSigningKey".equals(command)) {
            fingerprintPrivateSigningKey(stdout, args[0]);
        } else if ("fingerprintPublicSigningKey".equals(command)) {
            fingerprintPublicSigningKey(stdout, args[0]);
        } else if ("fingerprintPrivateEncryptionKey".equals(command)) {
            fingerprintPrivateEncryptionKey(stdout, args[0]);
        } else if ("fingerprintPublicEncryptionKey".equals(command)) {
            fingerprintPublicEncryptionKey(stdout, args[0]);
        } else if ("decryptSignedMessage".equals(command)) {
            decryptSignedMessage(CLI_MESSAGE,
                args[0], args[1], args[2], args[3]);
        } else if ("genEncryptedSignedMessage".equals(command)) {
            genEncryptedSignedMessage(CLI_MESSAGE, args);
        } else if ("speedTest".equals(command)) {
            speedTest();
        } else {
            throw new IllegalArgumentException("Command not recognised: " + command);
        }
    }

    /**
     * Call main with stdout as the output stream.
     * This exists just to minimise the scope of warning suppression.
     */
    @SuppressWarnings("squid:S106")
    private static void mainWithStdout(final String[] args, final Openable[] openables)
            throws IOException, InvalidInputException {
        main(System.out, args[0], openables);
    }
    
    public static void main(final String[] args) {
        final Openable[] openables = new Openable[args.length-1];
        for (int i = 0; i < args.length-1; i++) {
            openables[i] = new FileOpenable(new File(args[i + 1]));
        }
        try {
            mainWithStdout(args, openables);
        } catch (final Exception ex) {
            log.error("Could not '{}': {}", args[0], ex.getMessage());
            log.debug("Exception:", ex);
            System.exit(2);
        }
    }


}
