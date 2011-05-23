package net.lshift.spki.suiteb;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertible;
import net.lshift.spki.convert.SexpName;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

/**
 * A SequenceItem encrypted with AES/GCM.
 */
public class AesPacket
    extends PositionBeanConvertible
    implements SequenceItem {
    public final AesKeyId keyId;
    public final byte[] nonce;
    public final byte[] ciphertext;

    @SexpName("aes-gcm-encrypted")
    public AesPacket(
        @P("keyId") AesKeyId keyId,
        @P("nonce") byte[] nonce,
        @P("ciphertext") byte[] ciphertext
    ) {
        super();
        this.keyId = keyId;
        this.nonce = nonce;
        this.ciphertext = ciphertext;
    }
}
