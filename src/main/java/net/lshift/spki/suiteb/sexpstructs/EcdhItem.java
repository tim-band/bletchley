package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.Condition;
import net.lshift.spki.suiteb.DigestSha384;
import net.lshift.spki.suiteb.InferenceEngine;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.SequenceItem;

/**
 * An ECDH session key packet
 */
@Convert.ByPosition(name = "suiteb-ecdh-aes-gcm-key",
fields={"sender", "recipient"})
public class EcdhItem implements SequenceItem {
    public final DigestSha384 sender;
    public final DigestSha384 recipient;

    private EcdhItem(final DigestSha384 sender, final DigestSha384 recipient) {
        super();
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

    public static EcdhItem ecdhItem(
        final PrivateEncryptionKey sender,
        final PublicEncryptionKey recipient) {
        return new EcdhItem(
            sender.getPublicKey().getKeyId(), recipient.getKeyId());
    }
}
