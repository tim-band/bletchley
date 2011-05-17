package net.lshift.spki.suiteb;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.InvalidCipherTextException;

import net.lshift.spki.ParseException;
import net.lshift.spki.suiteb.sexpstructs.ECDHMessage;
import net.lshift.spki.suiteb.sexpstructs.EncryptedKey;
import net.lshift.spki.suiteb.sexpstructs.EncryptionRecipients;
import net.lshift.spki.suiteb.sexpstructs.MultipleRecipientEncryptedMessage;

/**
 * Encrypt/decrypt messages intended for multiple recipients.
 */
public class MultipleRecipient
{
    public static <T> MultipleRecipientEncryptedMessage encrypt(
        Class<T> messageType,
        List<PublicEncryptionKey> publicKeys,
        T message)
    {
        // FIXME: use a special type for AES GCM keys
        byte[] key = EC.generateAESKey();
        EncryptedKey wKey = new EncryptedKey(key);
        List<ECDHMessage> recipients = new ArrayList<ECDHMessage>();
        for (PublicEncryptionKey pKey: publicKeys) {
            recipients.add(pKey.encrypt(EncryptedKey.class, wKey));
        }
        return new MultipleRecipientEncryptedMessage(
            new EncryptionRecipients(recipients),
            EC.symmetricEncrypt(messageType, key, message));
    }

    public static <T> T decrypt(
        Class<T> messageType,
        PrivateEncryptionKey k,
        MultipleRecipientEncryptedMessage packet)
        throws InvalidCipherTextException,
            ParseException
    {
        DigestSha384 keyId = k.getPublicKey().getKeyId();
        for (ECDHMessage recipient: packet.getRecipients().getRecipients()) {
            if (keyId.equals(recipient.getRecipient())) {
                EncryptedKey payloadKey
                    = k.decrypt(EncryptedKey.class, recipient);
                return EC.symmetricDecrypt(messageType,
                    payloadKey.getKey(), packet.getCiphertext());
            }
        }
        throw new RuntimeException("No message for us found");
    }
}
