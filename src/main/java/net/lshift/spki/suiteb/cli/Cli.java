package net.lshift.spki.suiteb.cli;

import static net.lshift.spki.convert.openable.OpenableUtils.write;
import static net.lshift.spki.suiteb.Signed.signed;
import static net.lshift.spki.suiteb.fingerprint.FingerprintUtils.getFingerprint;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.AdvancedSpkiInputStream;
import net.lshift.spki.CanonicalSpkiOutputStream;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.convert.ConverterCatalog;
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
import net.lshift.spki.suiteb.simplemessage.SimpleMessage;

/**
 * Command line interface to crypto functions
 */
public class Cli {
    private static final String CLI_MESSAGE = Cli.class.toString();
    private static ConverterCatalog R = ConverterCatalog.BASE.extend(SimpleMessage.class);

    private static <U> U read(final Class<U> clazz, final Openable open)
        throws IOException, InvalidInputException {
        return OpenableUtils.read(R, clazz, open);
    }

    private static SequenceItem read(final Openable open)
        throws IOException, InvalidInputException {
        return read(SequenceItem.class, open);
    }

    public static void prettyPrint(final Openable file)
        throws IOException,
            ParseException {
        PrettyPrinter.prettyPrint(new PrintWriter(System.out), file.read());
    }

    public static void prettyPrintToFile(final Openable in, final Openable out)
                    throws ParseException, IOException {
        final PrintWriter pw = new PrintWriter(out.write());
        PrettyPrinter.prettyPrint(pw, in.read());
        pw.close();
    }

    public static void canonical(final Openable in, final Openable out) throws IOException, ParseException {
        // FIXME: this doesn't live here
        PrettyPrinter.copyStream(
            new AdvancedSpkiInputStream(in.read()),
            new CanonicalSpkiOutputStream(out.write()));
    }

    public static void genSigningKey(final Openable out)
        throws IOException {
        write(out, PrivateSigningKey.generate());
    }

    public static void genEncryptionKey(final Openable out)
        throws IOException {
        write(out, PrivateEncryptionKey.generate());
    }

    public static void getPublicSigningKey(final Openable privk, final Openable pubk)
        throws IOException, InvalidInputException {
        final PrivateSigningKey privatek = read(PrivateSigningKey.class, privk);
        write(pubk, privatek.getPublicKey());
    }

    public static void getPublicEncryptionKey(final Openable privk, final Openable pubk)
        throws IOException, InvalidInputException {
        final PrivateEncryptionKey privatek
            = read(PrivateEncryptionKey.class, privk);
        write(pubk, privatek.getPublicKey());
    }

    public static void fingerprintPrivateSigningKey(
        final PrintStream stdout,
        final Openable privk) throws IOException, InvalidInputException {
        stdout.println(getFingerprint(
            read(PrivateSigningKey.class, privk).getPublicKey().getKeyId()));
    }

    public static void fingerprintPublicSigningKey(
        final PrintStream stdout,
        final Openable pubk) throws IOException, InvalidInputException {
        stdout.println(getFingerprint(
            read(PublicSigningKey.class, pubk).getKeyId()));
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
        final InferenceEngine inference = new InferenceEngine(R);
        inference.processTrusted(signingKey);
        inference.process(encryptionKey);
        inference.process(read(packet));
        final SimpleMessage message
            = inference.getSoleAction(SimpleMessage.class);
        if (!messageType.equals(message.type)) {
            throw new RuntimeException("Message was not of expected type");
        }
        OpenableUtils.writeBytes(out, message.content);
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
        final Action message = new Action(new SimpleMessage(
            messageType, OpenableUtils.readBytes(args[1])));
        final PrivateSigningKey privateKey
            = read(PrivateSigningKey.class, args[0]);
        encryptedSequenceItems.add(privateKey.sign(message));
        encryptedSequenceItems.add(signed(message));

        sequenceItems.add(aesKey.encrypt(new Sequence(encryptedSequenceItems)));

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
            prettyPrint(args[0]);
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
            throw new RuntimeException("Command not recognised: " + command);
        }
    }

    public static void main(final String[] args) {
        final Openable[] openables = new Openable[args.length-1];
        for (int i = 0; i < args.length-1; i++) {
            openables[i] = new FileOpenable(new File(args[i + 1]));
        }
        try {
            main(System.out, args[0], openables);
        } catch (final Exception ex) {
            System.err.println("Could not '" + args[0] + "':");
            ex.printStackTrace();
            System.exit(2);
        }
    }
}
