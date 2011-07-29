package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.Convert;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Serialization format for ECDH shared secret before it's hashed into
 * a GCM key.
 */
@Convert.NeedsConverter(ECPointConverter.class)
@Convert.ByPosition(name="suiteb-p384-ecdh-shared-secret",
    fields={"receiverKey", "senderKey", "sharedSecret"})
public class EcdhSharedSecret {
    public final ECPoint receiverKey;
    public final ECPoint senderKey;
    public final BigInteger sharedSecret;

    public EcdhSharedSecret(
        final ECPoint receiverKey,
        final ECPoint senderKey,
        final BigInteger sharedSecret
    ) {
        super();
        this.receiverKey = receiverKey;
        this.senderKey = senderKey;
        this.sharedSecret = sharedSecret;
    }
}
