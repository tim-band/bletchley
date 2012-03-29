package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.Condition;
import net.lshift.spki.suiteb.DigestSha384;
import net.lshift.spki.suiteb.InferenceEngine;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.SequenceItem;

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

    @Override
    public void process(final InferenceEngine engine, final Condition trust)
                    throws InvalidInputException {
        final PrivateEncryptionKey key = engine.getPrivateEncryptionKey(recipient);
        if (key != null) {
            engine.process(key.getKey(ephemeralKey), trust);
        }
    }
}
