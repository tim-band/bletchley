package net.lshift.spki.suiteb.cli;

import static net.lshift.spki.convert.OpenableUtils.read;
import static net.lshift.spki.convert.OpenableUtils.readBytes;
import static net.lshift.spki.convert.OpenableUtils.write;
import static net.lshift.spki.convert.OpenableUtils.writeBytes;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.ParseException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.SExp;
import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.FileOpenable;
import net.lshift.spki.convert.Openable;
import net.lshift.spki.suiteb.DigestSha384;
import net.lshift.spki.suiteb.MultipleRecipient;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.PublicSigningKey;
import net.lshift.spki.suiteb.sexpstructs.ECDHMessage;
import net.lshift.spki.suiteb.sexpstructs.MultipleRecipientEncryptedMessage;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;
import net.lshift.spki.suiteb.sexpstructs.SimpleSigned;

import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Command line interface to crypto functions
 */
public class CLI
{
    private static final String CLI_MESSAGE = CLI.class.toString();

    public static void prettyPrint(Openable file)
        throws IOException,
            ParseException
    {
        PrettyPrinter.prettyPrint(System.out,
            read(SExp.class, file));
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

    public static void genEncryptedSignedMessage(
        String messageType,
        Openable sPrivate,
        Openable ePublic,
        Openable message,
        Openable out) throws IOException, ParseException
    {
        PrivateSigningKey dsaPrivate = read(PrivateSigningKey.class, sPrivate);
        PublicEncryptionKey dhPublic = read(PublicEncryptionKey.class, ePublic);
        SExp messageSexp = Convert.toSExp(SimpleMessage.class,
            new SimpleMessage(messageType, readBytes(message)));
        SimpleSigned signed = new SimpleSigned(messageSexp,
            dsaPrivate.sign(DigestSha384.digest(messageSexp)));
        ECDHMessage encrypted = dhPublic.encrypt(SimpleSigned.class, signed);
        write(out, ECDHMessage.class, encrypted);
    }

    public static void decryptSignedMessage(
        String messageType,
        Openable ePrivate,
        Openable sPublic,
        Openable packet,
        Openable out)
        throws ParseException,
            IOException,
            InvalidCipherTextException
    {
        PrivateEncryptionKey dhPrivate = read(PrivateEncryptionKey.class,
            ePrivate);
        PublicSigningKey dsaPublic = read(PublicSigningKey.class, sPublic);
        ECDHMessage encrypted = read(ECDHMessage.class, packet);
        SimpleSigned signed = dhPrivate.decrypt(SimpleSigned.class, encrypted);
        if (!dsaPublic.validate(DigestSha384.digest(signed.object),
            signed.signature)) {
            throw new RuntimeException("Signature validation failure");
        }
        SimpleMessage message = Convert.fromSExp(SimpleMessage.class,
            signed.object);
        if (!messageType.equals(message.type)) {
            throw new RuntimeException("Message is of an unexpected type");
        }
        writeBytes(out, message.content);
    }

    private static void genEncryptedSignedMRMessage(
        String messageType,
        Openable[] args) throws ParseException, IOException
    {
        int i = 0;
        PrivateSigningKey dsaPrivate = read(PrivateSigningKey.class, args[i++]);
        SExp messageSexp = Convert.toSExp(SimpleMessage.class,
            new SimpleMessage(messageType, readBytes(args[i++])));
        SimpleSigned signed = new SimpleSigned(messageSexp,
            dsaPrivate.sign(DigestSha384.digest(messageSexp)));
        List<PublicEncryptionKey> publicKeys
            = new ArrayList<PublicEncryptionKey>();
        for (; i < args.length -1; i++) {
            publicKeys.add(read(PublicEncryptionKey.class, args[i]));
        }
        MultipleRecipientEncryptedMessage packet
            = MultipleRecipient.encrypt(SimpleSigned.class, publicKeys, signed);
        write(args[args.length -1],
            MultipleRecipientEncryptedMessage.class, packet);
    }

    private static void decryptSignedMRMessage(
        String messageType,
        Openable ePrivate,
        Openable sPublic,
        Openable packet,
        Openable out)
        throws ParseException,
            IOException,
            InvalidCipherTextException
    {
        PrivateEncryptionKey dhPrivate = read(PrivateEncryptionKey.class,
            ePrivate);
        PublicSigningKey dsaPublic = read(PublicSigningKey.class, sPublic);
        SimpleSigned signed = MultipleRecipient.decrypt(
            SimpleSigned.class, dhPrivate,
            read(MultipleRecipientEncryptedMessage.class, packet));
        if (!dsaPublic.validate(DigestSha384.digest(signed.object),
            signed.signature)) {
            throw new RuntimeException("Signature validation failure");
        }
        SimpleMessage message = Convert.fromSExp(SimpleMessage.class,
            signed.object);
        if (!messageType.equals(message.type)) {
            throw new RuntimeException("Message is of an unexpected type");
        }
        writeBytes(out, message.content);
    }

    public static void main(String command, Openable... args)
        throws FileNotFoundException,
            ParseException,
            IOException,
            InvalidCipherTextException
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
        } else if ("genEncryptedSignedMessage".equals(command)) {
            genEncryptedSignedMessage(CLI_MESSAGE,
                args[0], args[1], args[2], args[3]);
        } else if ("decryptSignedMessage".equals(command)) {
            decryptSignedMessage(CLI_MESSAGE,
                args[0], args[1], args[2], args[3]);
        } else if ("genEncryptedSignedMRMessage".equals(command)) {
            genEncryptedSignedMRMessage(CLI_MESSAGE, args);
        } else if ("decryptSignedMRMessage".equals(command)) {
            decryptSignedMRMessage(CLI_MESSAGE,
                args[0], args[1], args[2], args[3]);
        } else {
            throw new RuntimeException("Command not recognised: " + command);
        }
    }

    public static void main(String[] args)
        throws FileNotFoundException,
            InvalidCipherTextException,
            ParseException,
            IOException
    {
        Openable[] openables = new Openable[args.length-1];
        for (int i = 0; i < args.length-1; i++) {
            openables[i] = new FileOpenable(new File(args[i+1]));
        }
        main(args[0], openables);
    }
}
