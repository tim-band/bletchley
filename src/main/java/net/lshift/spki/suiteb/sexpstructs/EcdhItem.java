package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SexpName;
import net.lshift.spki.suiteb.DigestSha384;

import org.bouncycastle.math.ec.ECPoint;

/**
 * An ECDH session key packet
 */
@Convert.ByPosition
public class EcdhItem implements SequenceItem {
    public final DigestSha384 recipient;
    public final ECPoint ephemeralKey;

    @SexpName("suiteb-ecdh-aes-gcm-key")
    public EcdhItem(
        @P("recipient") DigestSha384 recipient,
        @P("ephemeralKey") ECPoint ephemeralKey
    ) {
        super();
        this.recipient = recipient;
        this.ephemeralKey = ephemeralKey;
    }
}
