package net.lshift.spki.suiteb;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

/**
 * A SequenceItem encrypted with AES/GCM.
 */
@Convert.ByPosition(name = "aes-gcm-encrypted",
    fields={"keyId", "nonce", "ciphertext"})
public class AesPacket implements SequenceItem {

    public final AesKeyId keyId;
    public final byte[] nonce;
    public final byte[] ciphertext;

    public AesPacket(
        AesKeyId keyId,
        byte[] nonce,
        byte[] ciphertext
    ) {
        super();
        this.keyId = keyId;
        this.nonce = nonce;
        this.ciphertext = ciphertext;
    }
}
