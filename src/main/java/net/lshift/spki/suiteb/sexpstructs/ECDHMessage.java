package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertable;
import net.lshift.spki.convert.SExpName;

import org.bouncycastle.math.ec.ECPoint;

public class ECDHMessage extends PositionBeanConvertable
{
    private final ECPoint ephemeralKey;
    private final byte[] ciphertext;

    @SExpName("suiteb-p384-ecdh-message")
    public ECDHMessage(
        @P("ephemeralKey") ECPoint ephemeralKey,
        @P("ciphertext") byte[] ciphertext)
    {
        super();
        this.ephemeralKey = ephemeralKey;
        this.ciphertext = ciphertext;
    }

    public ECPoint getEphemeralKey()
    {
        return ephemeralKey;
    }

    public byte[] getCiphertext()
    {
        return ciphertext;
    }
}
