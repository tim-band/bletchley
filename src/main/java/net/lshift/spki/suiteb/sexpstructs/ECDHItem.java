package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertable;
import net.lshift.spki.convert.SExpName;
import net.lshift.spki.suiteb.AESKeyId;
import net.lshift.spki.suiteb.DigestSha384;

import org.bouncycastle.math.ec.ECPoint;

public class ECDHItem extends PositionBeanConvertable
    implements SequenceItem
{
    public final DigestSha384 recipient;
    public final AESKeyId keyId;
    public final ECPoint ephemeralKey;

    @SExpName("suiteb-ecdh-aes-gcm-key")
    public ECDHItem(
        @P("recipient") DigestSha384 recipient,
        @P("keyId") AESKeyId keyId,
        @P("ephemeralKey") ECPoint ephemeralKey
    ) {
        super();
        this.recipient = recipient;
        this.keyId = keyId;
        this.ephemeralKey = ephemeralKey;
    }
}
