package net.lshift.spki.suiteb.cli;

import static net.lshift.spki.convert.openable.OpenableUtils.read;
import static net.lshift.spki.convert.openable.OpenableUtils.write;
import static net.lshift.spki.suiteb.fingerprint.FingerprintUtils.getFingerprint;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.AdvancedSpkiInputStream;
import net.lshift.spki.CanonicalSpkiOutputStream;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.convert.Registry;
import net.lshift.spki.convert.openable.FileOpenable;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.convert.openable.OpenableUtils;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.ActionType;
import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.InferenceEngine;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.PublicSigningKey;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.simplemessage.SimpleMessage;

/**
 * Command line interface to crypto functions
 */
public class Cli {
    private static final String CLI_MESSAGE = Cli.class.toString();

    public static void prettyPrint(final Openable file)
        throws IOException,
            ParseException {
        PrettyPrinter.prettyPrint(System.out, file.read());
    }

    public static void prettyPrintToFile(Openable in, Openable out)
                    throws ParseException, IOException {
        PrettyPrinter.prettyPrint(out.write(), in.read());
    }

    public static void canonical(Openable in, Openable out) throws IOException, ParseException {
        // FIXME: this doesn't live here
        PrettyPrinter.copyStream(
            new AdvancedSpkiInputStream(in.read()),
            new CanonicalSpkiOutputStream(out.write()));
    }

    public static void genEncryptionKey(final Openable out)
        throws IOException {
        write(PrivateEncryptionKey.class, PrivateEncryptionKey.generate(),
            out);
    }

    public static void getPublicEncryptionKey(final Openable privk, final Openable pubk)
        throws IOException, InvalidInputException {
        final PrivateEncryptionKey privatek
            = read(PrivateEncryptionKey.class, privk);
        write(PublicEncryptionKey.class, privatek.getPublicKey(), pubk);
    }

    public static void genSigningKey(final Openable out)
        throws IOException {
        write(PrivateSigningKey.class, PrivateSigningKey.generate(), out);
    }

    public static void getPublicSigningKey(final Openable privk, final Openable pubk)
        throws IOException, InvalidInputException {
        final PrivateSigningKey privatek = read(PrivateSigningKey.class, privk);
        write(PublicSigningKey.class, privatek.getPublicKey(), pubk);
    }

    public static void fingerprintPrivateSigningKey(
        PrintStream stdout,
        Openable privk) throws IOException, InvalidInputException {
        stdout.println(getFingerprint(
            read(PrivateSigningKey.class, privk).getPublicKey().getKeyId()));
    }

    public static void fingerprintPublicSigningKey(
        PrintStream stdout,
        Openable pubk) throws IOException, InvalidInputException {
        stdout.println(getFingerprint(
            read(PublicSigningKey.class, pubk).getKeyId()));
    }

    public static void fingerprintPrivateEncryptionKey(
        PrintStream stdout,
        Openable privk) throws IOException, InvalidInputException {
        stdout.println(getFingerprint(
            read(PrivateEncryptionKey.class, privk).getPublicKey().getKeyId()));
    }

    public static void fingerprintPublicEncryptionKey(
        PrintStream stdout,
        Openable pubk) throws IOException, InvalidInputException {
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
        final InferenceEngine inference = new InferenceEngine();
        inference.addTrustedKey(signingKey.getKeyId());
        inference.process(signingKey);
        inference.process(encryptionKey);
        inference.process(read(SequenceItem.class, packet));
        final List<ActionType> messages = inference.getActions();
        if (messages.size() != 1) {
            throw new RuntimeException("Did not find exactly one signed message");
        }
        if (!(messages.get(0) instanceof SimpleMessage)) {
            throw new RuntimeException("Signed object was not message");
        }
        final SimpleMessage message = (SimpleMessage) messages.get(0);
        if (!messageType.equals(message.type)) {
            throw new RuntimeException("Message was not of expected type");
        }
        OpenableUtils.writeBytes(message.content, out);
    }

    public static void decryptSignedMessage(
        final String messageType,
        final Openable ePrivate,
        final Openable sPublic,
        final Openable packet,
        final Openable out)
        throws IOException, InvalidInputException {
        final PrivateEncryptionKey encryptionKey = read(PrivateEncryptionKey.class, ePrivate);
        final PublicSigningKey signingKey = read(PublicSigningKey.class, sPublic);
        decryptSignedMessage(messageType, encryptionKey, signingKey, packet, out);
    }

    public static void genEncryptedSignedMessage(
        final String messageType,
        final Openable[] args)
        throws IOException, InvalidInputException {
        final List<SequenceItem> sequenceItems = new ArrayList<SequenceItem>();
        final AesKey aesKey = AesKey.generateAESKey();
        for (int i = 2; i < args.length - 1; i++) {
            final PublicEncryptionKey pKey = read(PublicEncryptionKey.class, args[i]);
            final AesKey rKey = pKey.setupEncrypt(sequenceItems);
            sequenceItems.add(rKey.encrypt(aesKey));
        }

        final List<SequenceItem> encryptedSequenceItems
            = new ArrayList<SequenceItem>();
        final Action message = new Action(new SimpleMessage(
            messageType, OpenableUtils.readBytes(args[1])));
        final PrivateSigningKey privateKey = read(PrivateSigningKey.class, args[0]);
        encryptedSequenceItems.add(privateKey.sign(message));
        encryptedSequenceItems.add(message);

        sequenceItems.add(aesKey.encrypt(new Sequence(encryptedSequenceItems)));

        write(Sequence.class, new Sequence(sequenceItems), args[args.length - 1]);
    }

    public static void speedTest() throws InvalidInputException {
        new SpeedTester().speedTest();
    }

    public static void main(PrintStream stdout, final String command, final Openable... args)
        throws IOException, InvalidInputException {
        Registry.getConverter(SimpleMessage.class);
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
        Openable[] openables = new Openable[args.length-1];
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
