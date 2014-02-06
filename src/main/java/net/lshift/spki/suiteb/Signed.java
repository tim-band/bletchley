package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.SexpBacked;

@Convert.ByPosition(name="signed", fields={"hashType", "payload"})
public class Signed extends SexpBacked implements SequenceItem {
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

    public static SequenceItem signed(
        final PrivateSigningKey key, final SequenceItem payload) {
        return sequence(key.sign(payload), signed(payload));
    }

    @Override
    public void process(final InferenceEngine engine, final Condition trust)
        throws InvalidInputException {
        if (!DigestSha384.DIGEST_NAME.equals(hashType)) {
            throw new CryptographyException(
                "Unknown hash type: " + hashType);
        }
        engine.process(payload,
            engine.getItemTrust(DigestSha384.digest(payload)));
    }
}
