package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.DigestSha384;

import org.bouncycastle.math.ec.ECPoint;

/**
 * An ECDH session key packet
 */
@Convert.ByPosition(name = "suiteb-ecdh-aes-gcm-key",
    fields={"recipient", "ephemeralKey"})
public class EcdhItem implements SequenceItem {
    public final DigestSha384 recipient;
    public final ECPoint ephemeralKey;

    public EcdhItem(
        final DigestSha384 recipient,
        final ECPoint ephemeralKey
    ) {
        super();
        this.recipient = recipient;
        this.ephemeralKey = ephemeralKey;
    }
}
