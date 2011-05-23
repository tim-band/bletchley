package net.lshift.spki.suiteb.cli;

import static net.lshift.spki.convert.OpenableUtils.read;
import static net.lshift.spki.convert.OpenableUtils.write;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.CanonicalSpkiInputStream;
import net.lshift.spki.ParseException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.convert.FileOpenable;
import net.lshift.spki.convert.Openable;
import net.lshift.spki.convert.OpenableUtils;
import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.InferenceEngine;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.PublicSigningKey;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceConversion;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;

/**
 * Command line interface to crypto functions
 */
public class Cli
{
    private static final String CLI_MESSAGE = Cli.class.toString();

    public static void prettyPrint(Openable file)
        throws IOException,
            ParseException
    {
        PrettyPrinter.prettyPrint(System.out,
            new CanonicalSpkiInputStream(file.read()));
    }

    public static void genEncryptionKey(Openable out) throws IOException
    {
        write(out, PrivateEncryptionKey.class,
            PrivateEncryptionKey.generate());
    }

    public static void getPublicEncryptionKey(Openable privk, Openable pubk)
        throws ParseException,
            IOException
    {
        final PrivateEncryptionKey privatek
            = read(PrivateEncryptionKey.class, privk);
        write(pubk, PublicEncryptionKey.class, privatek.getPublicKey());
    }

    public static void genSigningKey(Openable out) throws IOException
    {
        write(out, PrivateSigningKey.class, PrivateSigningKey.generate());
    }

    public static void getPublicSigningKey(Openable privk, Openable pubk)
        throws ParseException,
            IOException
    {
        final PrivateSigningKey privatek = read(PrivateSigningKey.class, privk);
        write(pubk, PublicSigningKey.class, privatek.getPublicKey());
    }

    public static void decryptSignedMessage(
        String messageType,
        Openable ePrivate,
        Openable sPublic,
        Openable packet,
        Openable out)
        throws ParseException,
            IOException
    {
        InferenceEngine inference = new InferenceEngine();
        PublicSigningKey signingKey = read(PublicSigningKey.class, sPublic);
        inference.process(signingKey);
        inference.process(read(PrivateEncryptionKey.class, ePrivate));
        inference.process(read(SequenceItem.class, packet));
        List<SequenceItem> signedBy
            = inference.getSignedBy(signingKey.getKeyId());
        if (signedBy.size() != 1) {
            throw new RuntimeException("Did not find exactly one signed message");
        }
        if (!(signedBy.get(0) instanceof SimpleMessage)) {
            throw new RuntimeException("Signed object was not message");
        }
        SimpleMessage message = (SimpleMessage) signedBy.get(0);
        if (!messageType.equals(message.type)) {
            throw new RuntimeException("Message was not of expected type");
        }
        OpenableUtils.writeBytes(out, message.content);
    }

    private static void genEncryptedSignedMessage(
        String messageType,
        Openable[] args) throws ParseException, IOException
    {
        List<SequenceItem> sequenceItems = new ArrayList<SequenceItem>();
        AesKey aesKey = AesKey.generateAESKey();
        for (int i = 2; i < args.length-1; i++) {
            PublicEncryptionKey pKey = read(PublicEncryptionKey.class, args[i]);
            AesKey rKey = pKey.setupEncrypt(sequenceItems);
            sequenceItems.add(rKey.encrypt(aesKey));
        }

        List<SequenceItem> encryptedSequenceItems
            = new ArrayList<SequenceItem>();
        SimpleMessage message = new SimpleMessage(
            messageType, OpenableUtils.readBytes(args[1]));
        encryptedSequenceItems.add(message);
        PrivateSigningKey privateKey = read(PrivateSigningKey.class, args[0]);
        encryptedSequenceItems.add(privateKey.sign(message));

        sequenceItems.add(aesKey.encrypt(new Sequence(encryptedSequenceItems)));

        write(args[args.length-1], Sequence.class, new Sequence(sequenceItems));
    }

    public static void main(String command, Openable... args)
        throws FileNotFoundException,
            ParseException,
            IOException
    {
        if ("prettyPrint".equals(command)) {
            prettyPrint(args[0]);
        } else if ("genSigningKey".equals(command)) {
            genSigningKey(args[0]);
        } else if ("genEncryptionKey".equals(command)) {
            genEncryptionKey(args[0]);
        } else if ("getPublicSigningKey".equals(command)) {
            getPublicSigningKey(args[0], args[1]);
        } else if ("getPublicEncryptionKey".equals(command)) {
            getPublicEncryptionKey(args[0], args[1]);
        } else if ("decryptSignedMessage".equals(command)) {
            decryptSignedMessage(CLI_MESSAGE,
                args[0], args[1], args[2], args[3]);
        } else if ("genEncryptedSignedMessage".equals(command)) {
            genEncryptedSignedMessage(CLI_MESSAGE, args);
        } else {
            throw new RuntimeException("Command not recognised: " + command);
        }
    }

    public static void main(String[] args)
        throws FileNotFoundException,
            ParseException,
            IOException
    {
        Openable[] openables = new Openable[args.length-1];
        for (int i = 0; i < args.length-1; i++) {
            openables[i] = new FileOpenable(new File(args[i+1]));
        }
        main(args[0], openables);
    }

    static {
        SequenceConversion.ensureInstalled();
    }
}
