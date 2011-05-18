package net.lshift.spki.suiteb;

import org.bouncycastle.crypto.InvalidCipherTextException;

import net.lshift.spki.ParseException;
import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertable;
import net.lshift.spki.convert.SExpName;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

public class AESKey extends PositionBeanConvertable implements SequenceItem
{
    public final AESKeyId keyId;
    public final byte[] key;

    @SExpName("aes-gcm-key")
    public AESKey(
        @P("keyId") AESKeyId keyId,
        @P("key") byte[] key
    ) {
        super();
        this.keyId = keyId;
        this.key = key;
    }

    public AESPacket encrypt(SequenceItem message)
    {
        byte[] nonce = EC.randomBytes(16);
        // FIXME: inline this
        byte[] ciphertext = EC.symmetricEncrypt(
            SequenceItem.class, key, nonce, message);
        return new AESPacket(keyId, nonce, ciphertext);
    }

    public SequenceItem decrypt(AESPacket packet) throws InvalidCipherTextException, ParseException
    {
        return EC.symmetricDecrypt(SequenceItem.class,
            key, packet.nonce, packet.ciphertext);
    }
}
