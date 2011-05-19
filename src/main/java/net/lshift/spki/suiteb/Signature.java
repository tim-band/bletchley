package net.lshift.spki.suiteb;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertable;
import net.lshift.spki.convert.SExpName;
import net.lshift.spki.suiteb.sexpstructs.ECDSASignature;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

/**
 * An SPKI signature, including the digest of the target object and
 * the id of the signing key.
 */
public class Signature extends PositionBeanConvertable
    implements SequenceItem
{
    public final DigestSha384 digest;
    public final DigestSha384 keyId;
    public final ECDSASignature rawSignature;

    @SExpName("signature")
    public Signature(
        @P("digest") DigestSha384 digest,
        @P("keyId") DigestSha384 keyId,
        @P("rawSignature") ECDSASignature rawSignature
    ) {
        this.digest = digest;
        this.keyId = keyId;
        this.rawSignature = rawSignature;
    }
}
