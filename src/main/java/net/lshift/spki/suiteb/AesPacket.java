package net.lshift.spki.suiteb;

import net.lshift.spki.convert.Convert;

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
        final AesKeyId keyId,
        final byte[] nonce,
        final byte[] ciphertext
    ) {
        super();
        this.keyId = keyId;
        this.nonce = nonce;
        this.ciphertext = ciphertext;
    }
}
