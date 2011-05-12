package net.lshift.spki.suiteb.cli;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import net.lshift.spki.Marshal;
import net.lshift.spki.ParseException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.SExp;
import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.DigestSha384;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.PublicSigningKey;
import net.lshift.spki.suiteb.sexpstructs.ECDHMessage;
import net.lshift.spki.suiteb.sexpstructs.ECDHPrivateKey;
import net.lshift.spki.suiteb.sexpstructs.ECDHPublicKey;
import net.lshift.spki.suiteb.sexpstructs.ECDSAPrivateKey;
import net.lshift.spki.suiteb.sexpstructs.ECDSAPublicKey;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;
import net.lshift.spki.suiteb.sexpstructs.SimpleSigned;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;

public class CLI
{
    private static final String CLI_MESSAGE = CLI.class.toString();

    public static byte[] generateEncryptionKey()
    {
        return Convert.toBytes(
            PrivateEncryptionKey.generate().pack());
    }

    public static byte[] getPublicEncryptionKey(byte[] dhPrivate)
    {
        try {
            return Convert.toBytes(
                PrivateEncryptionKey.unpack(
                    Convert.fromBytes(ECDHPrivateKey.class, dhPrivate))
                    .getPublicKey().pack());
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] generateSigningKey()
    {
        return Convert.toBytes(
            PrivateSigningKey.generate().pack());
    }

    public static byte[] getPublicSigningKey(byte[] dsaPrivate)
    {
        try {
            return Convert.toBytes(
                PrivateSigningKey.unpack(
                    Convert.fromBytes(ECDSAPrivateKey.class, dsaPrivate))
                    .getPublicKey().pack());
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] generateEncryptedSignedMessage(
        byte[] sPrivate,
        byte[] ePublic,
        String messageType,
        byte[] message)
    {
        try {
            PrivateSigningKey dsaPrivate = PrivateSigningKey.unpack(
                Convert.fromBytes(ECDSAPrivateKey.class, sPrivate));
            PublicEncryptionKey dhPublic = PublicEncryptionKey.unpack(
                Convert.fromBytes(ECDHPublicKey.class, ePublic));
            SExp messageSexp = Convert.toSExp(
                new SimpleMessage(messageType, message));
            SimpleSigned signed = new SimpleSigned(messageSexp,
                dsaPrivate.sign(DigestSha384.digest(messageSexp)));
            ECDHMessage encrypted = dhPublic.encrypt(Convert.toSExp(signed));
            return Convert.toBytes(encrypted);
        } catch (ParseException e) {
            // TODO Auto-generated catch block
            throw new RuntimeException(e);
        }
    }

    public static byte[] decryptSignedMessage(
        byte[] ePrivate,
        byte[] sPublic,
        String messageType,
        byte[] packet)
    {
        try {
            PrivateEncryptionKey dhPrivate = PrivateEncryptionKey.unpack(
                Convert.fromBytes(ECDHPrivateKey.class, ePrivate));
            PublicSigningKey dsaPublic = PublicSigningKey.unpack(
                Convert.fromBytes(ECDSAPublicKey.class, sPublic));
            ECDHMessage encrypted = Convert.fromBytes(ECDHMessage.class, packet);
            SExp decrypted = dhPrivate.decrypt(encrypted);
            SimpleSigned signed = Convert.fromSExp(SimpleSigned.class, decrypted);
            if (!dsaPublic.validate(DigestSha384.digest(signed.getObject()),
                signed.getSignature())) {
                throw new RuntimeException("Signature validation failure");
            }
            SimpleMessage message = Convert.fromSExp(SimpleMessage.class, signed.getObject());
            if (!messageType.equals(message.getType())) {
                throw new RuntimeException("Message is of an unexpected type");
            }
            return message.getContent();
        } catch (ParseException e) {
            throw new RuntimeException(e);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> T read(Class<T> class1, File file) {
        try {
            return Convert.fromSExp(class1,
                Marshal.unmarshal(new FileInputStream(file)));
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> void write(File file, T o) {
        try {
            Marshal.marshal(new FileOutputStream(file),
                Convert.toSExp(o));
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args)
        throws FileNotFoundException,
            ParseException,
            IOException,
            InvalidCipherTextException
    {
        String command = args[0];
        File[] files = new File[args.length-1];
        for (int i = 0; i < args.length-1; i++) {
            files[i] = new File(args[i+1]);
        }
        if ("prettyprint".equals(command)) {
            PrettyPrinter.prettyPrint(System.out,
                Marshal.unmarshal(new FileInputStream(files[0])));
        } else if ("genSigningKey".equals(command)) {
            write(files[0], PrivateSigningKey.generate().pack());
        } else if ("genEncryptionKey".equals(command)) {
            write(files[0], PrivateEncryptionKey.generate().pack());
        } else if ("getPublicSigningKey".equals(command)) {
            write(files[1], PrivateSigningKey.unpack(
                read(ECDSAPrivateKey.class, files[0])).getPublicKey().pack());
        } else if ("getPublicEncryptionKey".equals(command)) {
            write(files[1], PrivateEncryptionKey.unpack(
                read(ECDHPrivateKey.class, files[0])).getPublicKey().pack());
        } else if ("genEncryptedSignedMessage".equals(command)) {
            PrivateSigningKey dsaPrivate = PrivateSigningKey.unpack(
                read(ECDSAPrivateKey.class, files[0]));
            PublicEncryptionKey dhPublic = PublicEncryptionKey.unpack(
                read(ECDHPublicKey.class, files[1]));
            byte[] message = IOUtils.toByteArray(new FileInputStream(files[2]));
            SExp messageSexp = Convert.toSExp(
                new SimpleMessage(CLI_MESSAGE, message));
            SimpleSigned signed = new SimpleSigned(messageSexp,
                dsaPrivate.sign(DigestSha384.digest(messageSexp)));
            ECDHMessage encrypted = dhPublic.encrypt(Convert.toSExp(signed));
            write(files[3], encrypted);
        } else if ("decryptSignedMessage".equals(command)) {
            PrivateEncryptionKey dhPrivate = PrivateEncryptionKey.unpack(
                read(ECDHPrivateKey.class, files[0]));
            PublicSigningKey dsaPublic = PublicSigningKey.unpack(
                read(ECDSAPublicKey.class, files[1]));
            ECDHMessage encrypted = read(ECDHMessage.class, files[2]);
            SExp decrypted = dhPrivate.decrypt(encrypted);
            SimpleSigned signed = Convert.fromSExp(SimpleSigned.class, decrypted);
            if (!dsaPublic.validate(DigestSha384.digest(signed.getObject()),
                signed.getSignature())) {
                throw new RuntimeException("Signature validation failure");
            }
            SimpleMessage message = Convert.fromSExp(SimpleMessage.class, signed.getObject());
            if (!CLI_MESSAGE.equals(message.getType())) {
                throw new RuntimeException("Message is of an unexpected type");
            }
            (new FileOutputStream(files[3])).write(message.getContent());
        } else {
            throw new RuntimeException("Command not recognised: " + command);
        }
    }
}
