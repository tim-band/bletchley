package net.lshift.spki.suiteb;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert;

/**
 * An ECDH session key packet
 */
@Convert.ByPosition(name = "suiteb-ecdh-aes-gcm-key",
fields={"sender", "recipient"})
public class EcdhItem implements SequenceItem {
    public final DigestSha384 sender;
    public final DigestSha384 recipient;

    public EcdhItem(final DigestSha384 sender, final DigestSha384 recipient) {
        this.sender = sender;
        this.recipient = recipient;
    }

    @Override
    public void process(final InferenceEngine engine, final Condition trust)
                    throws InvalidInputException {
        final PrivateEncryptionKey privs = engine.getPrivateEncryptionKey(sender);
        final PrivateEncryptionKey privr = engine.getPrivateEncryptionKey(recipient);
        final PublicEncryptionKey pubs = engine.getPublicEncryptionKey(sender);
        final PublicEncryptionKey pubr = engine.getPublicEncryptionKey(recipient);
        if (privr != null && pubs != null) {
            engine.process(privr.getKeyAsReceiver(pubs), trust);
        } else if (privs != null && pubr != null) {
            engine.process(privs.getKeyAsSender(pubr), trust);
        }
    }
}
