package net.lshift.spki.suiteb;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.sexpstructs.EcdsaSignature;

/**
 * An SPKI signature, including the digest of the target object and
 * the id of the signing key.
 */
@Convert.ByPosition(name="signature",
    fields={"digest", "keyId", "rawSignature"})
public class Signature implements SequenceItem {
    public final DigestSha384 digest;
    public final DigestSha384 keyId;
    public final EcdsaSignature rawSignature;

    public Signature(
        final DigestSha384 digest,
        final DigestSha384 keyId,
        final EcdsaSignature rawSignature
    ) {
        this.digest = digest;
        this.keyId = keyId;
        this.rawSignature = rawSignature;
    }
}
