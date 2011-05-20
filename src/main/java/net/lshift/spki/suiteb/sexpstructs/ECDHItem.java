package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertible;
import net.lshift.spki.convert.SExpName;
import net.lshift.spki.suiteb.DigestSha384;

import org.bouncycastle.math.ec.ECPoint;

/**
 * An ECDH session key packet
 */
public class ECDHItem extends PositionBeanConvertible
    implements SequenceItem
{
    public final DigestSha384 recipient;
    public final ECPoint ephemeralKey;

    @SExpName("suiteb-ecdh-aes-gcm-key")
    public ECDHItem(
        @P("recipient") DigestSha384 recipient,
        @P("ephemeralKey") ECPoint ephemeralKey
    ) {
        super();
        this.recipient = recipient;
        this.ephemeralKey = ephemeralKey;
    }
}
