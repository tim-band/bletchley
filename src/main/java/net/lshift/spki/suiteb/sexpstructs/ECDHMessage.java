package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertable;
import net.lshift.spki.convert.SExpName;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Serialization format for ECDH-encrypted messages
 */
public class ECDHMessage extends PositionBeanConvertable
{
    private final ECPoint ephemeralKey;
    private final byte[] encryptedPayloadKey;
    private final byte[] ciphertext;

    @SExpName("suiteb-p384-ecdh-message")
    public ECDHMessage(
        @P("ephemeralKey") ECPoint ephemeralKey,
        @P("encryptedPayloadKey") byte[] encryptedPayloadKey,
        @P("ciphertext") byte[] ciphertext)
    {
        super();
        this.ephemeralKey = ephemeralKey;
        this.encryptedPayloadKey = encryptedPayloadKey;
        this.ciphertext = ciphertext;
    }

    public ECPoint getEphemeralKey()
    {
        return ephemeralKey;
    }

    public byte[] getEncryptedPayloadKey()
    {
        return encryptedPayloadKey;
    }

    public byte[] getCiphertext()
    {
        return ciphertext;
    }
}
