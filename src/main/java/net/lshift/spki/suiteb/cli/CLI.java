package net.lshift.spki.suiteb.cli;

import net.lshift.spki.ParseException;
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

import org.bouncycastle.crypto.InvalidCipherTextException;

public class CLI
{
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

}
