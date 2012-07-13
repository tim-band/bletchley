package net.lshift.spki.suiteb;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.SexpBacked;
import net.lshift.spki.suiteb.sexpstructs.EcdsaSignature;

/**
 * An SPKI signature, including the digest of the target object and
 * the id of the signing key.
 */
@Convert.ByPosition(name="signature",
    fields={"digest", "keyId", "rawSignature"})
public class Signature extends SexpBacked implements SequenceItem {
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

    @Override
    public void process(final InferenceEngine engine, final Condition trust)
        throws InvalidInputException {
        final PublicSigningKey pKey = engine.getPublicSigningKey(keyId);
        if (pKey == null) {
            return;
        }
        if (!pKey.validate(digest, rawSignature))
            throw new CryptographyException("Sig validation failure");
        engine.addItemTrust(digest, engine.getItemTrust(keyId));
    }
}
