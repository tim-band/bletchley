package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionalSexp;

public class ECDHMessage
{
    private final ECDHPublicKey ephemeralKey;
    private final byte[] ciphertext;

    @PositionalSexp("suiteb-p384-ecdh-message")
    public ECDHMessage(
        @P("ephemeralKey") ECDHPublicKey ephemeralKey,
        @P("ciphertext") byte[] ciphertext)
    {
        super();
        this.ephemeralKey = ephemeralKey;
        this.ciphertext = ciphertext;
    }

    public ECDHPublicKey getEphemeralKey()
    {
        return ephemeralKey;
    }

    public byte[] getCiphertext()
    {
        return ciphertext;
    }
}
