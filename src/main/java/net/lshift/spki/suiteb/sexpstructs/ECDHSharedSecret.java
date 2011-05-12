package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionalSexp;

public class ECDHSharedSecret
{
    private final ECDHPublicKey receiverKey;
    private final ECDHPublicKey senderKey;
    private final BigInteger sharedSecret;

    @PositionalSexp("suiteb-p384-ecdh-shared-secret")
    public ECDHSharedSecret(
        @P("receiverKey") ECDHPublicKey receiverKey,
        @P("senderKey") ECDHPublicKey senderKey,
        @P("sharedSecret") BigInteger sharedSecret)
   {
        super();
        this.receiverKey = receiverKey;
        this.senderKey = senderKey;
        this.sharedSecret = sharedSecret;
    }

    public ECDHPublicKey getReceiverKey()
    {
        return receiverKey;
    }

    public ECDHPublicKey getSenderKey()
    {
        return senderKey;
    }

    public BigInteger getSharedSecret()
    {
        return sharedSecret;
    }
}
