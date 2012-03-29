package net.lshift.spki.suiteb;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert;

@Convert.ByPosition(name="signed", fields={"hashType", "payload"})
public class Signed implements SequenceItem {
    public final String hashType;
    public final SequenceItem payload;

    public Signed(final String hashType, final SequenceItem payload) {
        super();
        this.hashType = hashType;
        this.payload = payload;
    }

    public static Signed signed(final SequenceItem payload) {
        return new Signed(DigestSha384.DIGEST_NAME, payload);
    }

    @Override
    public void process(final InferenceEngine engine, final Condition trust)
        throws InvalidInputException {
        if (!DigestSha384.DIGEST_NAME.equals(hashType)) {
            throw new CryptographyException(
                "Unknown hash type: " + hashType);
        }
        final DigestSha384 digest = DigestSha384.digest(payload);
        final Condition itemTrust = engine.getItemTrust(digest);
        if (itemTrust != null) {
            engine.process(payload, itemTrust);
        }
    }
}
