package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertable;
import net.lshift.spki.convert.SExpName;
import net.lshift.spki.suiteb.DigestSha384;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Serialization format for ECDH-encrypted messages
 */
public class ECDHMessage extends PositionBeanConvertable
{
    private final DigestSha384 recipient;
    private final ECPoint ephemeralKey;
    private final byte[] ciphertext;

    @SExpName("suiteb-p384-ecdh-message")
    public ECDHMessage(
        @P("recipient") DigestSha384 recipient,
        @P("ephemeralKey") ECPoint ephemeralKey,
        @P("ciphertext") byte[] ciphertext)
    {
        super();
        this.recipient = recipient;
        this.ephemeralKey = ephemeralKey;
        this.ciphertext = ciphertext;
    }

    public DigestSha384 getRecipient()
    {
        return recipient;
    }

    public ECPoint getEphemeralKey()
    {
        return ephemeralKey;
    }

    public byte[] getCiphertext()
    {
        return ciphertext;
    }

    static {
        Point.ensureRegistered();
    }
}
