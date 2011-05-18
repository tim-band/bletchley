package net.lshift.spki.suiteb;

import java.util.List;

import net.lshift.spki.ParseException;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Encrypt/decrypt messages intended for multiple recipients.
 */
public class MultipleRecipient
{
    public static <T> SequenceItem encrypt(
        Class<T> messageType,
        List<PublicEncryptionKey> publicKeys,
        T message)
    {
        return null;
//        // FIXME: use a special type for AES GCM keys
//        byte[] key = EC.generateAESKey();
//        EncryptedKey wKey = new EncryptedKey(key);
//        List<ECDHMessage> recipients = new ArrayList<ECDHMessage>();
//        for (PublicEncryptionKey pKey: publicKeys) {
//            recipients.add(pKey.encrypt(EncryptedKey.class, wKey));
//        }
//        return new MultipleRecipientEncryptedMessage(
//            new EncryptionRecipients(recipients),
//            EC.symmetricEncrypt(messageType, key, message));
    }

    public static <T> T decrypt(
        Class<T> messageType,
        PrivateEncryptionKey k,
        SequenceItem packet)
        throws InvalidCipherTextException,
            ParseException
    {
        return null;
//        DigestSha384 keyId = k.getPublicKey().getKeyId();
//        for (ECDHMessage recipient: packet.recipients.recipients) {
//            if (keyId.equals(recipient.recipient)) {
//                EncryptedKey payloadKey
//                    = k.decrypt(EncryptedKey.class, recipient);
//                return EC.symmetricDecrypt(messageType,
//                    payloadKey.key, packet.ciphertext);
//            }
//        }
//        throw new RuntimeException("No message for us found");
    }
}
