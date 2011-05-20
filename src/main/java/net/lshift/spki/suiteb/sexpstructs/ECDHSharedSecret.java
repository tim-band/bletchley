package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertible;
import net.lshift.spki.convert.SExpName;

/**
 * Serialization format for ECDH shared secret before it's hashed into
 * a GCM key.
 */
public class ECDHSharedSecret extends PositionBeanConvertible
{
    public final ECPoint receiverKey;
    public final ECPoint senderKey;
    public final BigInteger sharedSecret;

    @SExpName("suiteb-p384-ecdh-shared-secret")
    public ECDHSharedSecret(
        @P("receiverKey") ECPoint receiverKey,
        @P("senderKey") ECPoint senderKey,
        @P("sharedSecret") BigInteger sharedSecret)
   {
        super();
        this.receiverKey = receiverKey;
        this.senderKey = senderKey;
        this.sharedSecret = sharedSecret;
    }

    static {
        Point.ensureRegistered();
    }
}
