package net.lshift.spki.suiteb;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertable;
import net.lshift.spki.convert.SExpName;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

/**
 * A SequenceItem encrypted with AES/GCM.
 */
public class AESPacket extends PositionBeanConvertable implements SequenceItem
{
    public final AESKeyId keyId;
    public final byte[] nonce;
    public final byte[] ciphertext;

    @SExpName("aes-gcm-encrypted")
    public AESPacket(
        @P("keyId") AESKeyId keyId,
        @P("nonce") byte[] nonce,
        @P("ciphertext") byte[] ciphertext)
    {
        super();
        this.keyId = keyId;
        this.nonce = nonce;
        this.ciphertext = ciphertext;
    }
}
