package net.lshift.spki.suiteb;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.suiteb.passphrase.PassphraseDelegate;
import net.lshift.spki.suiteb.passphrase.PassphraseProtectedKey;
import net.lshift.spki.suiteb.sexpstructs.EcdhItem;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Take a bunch of SequenceItems and figure out what you can infer from them.
 * Decrypt what you can decrypt, check the signatures you can check and so on.
 * ORDER MATTERS for the moment, but we could fix that if need be.
 * Full of limitations, but the principle is there, the limitations can be
 * fixed and it will do for now.
 */
public class InferenceEngine {
    private static final Logger LOG
        = LoggerFactory.getLogger(InferenceEngine.class);

    private final Map<DigestSha384, PrivateEncryptionKey> dhKeys
        = new HashMap<DigestSha384, PrivateEncryptionKey>();
    private final Map<DigestSha384, PublicSigningKey> dsaKeys
        = new HashMap<DigestSha384, PublicSigningKey>();
    private final Map<AesKeyId, AesKey> aesKeys
        = new HashMap<AesKeyId, AesKey>();
    private final Map<DigestSha384, DigestSha384> signedBy
        = new HashMap<DigestSha384, DigestSha384>();

    private boolean blindlyTrusting = false;
    private final Set<DigestSha384> trustedKeys
        = new HashSet<DigestSha384>();
    private final List<ActionType> actions
        = new ArrayList<ActionType>();

    private final Map<String, String> byteNames = new HashMap<String,String>();

    private PassphraseDelegate passphraseDelegate;

    private String bytesString(final byte[] bytes) {
        final String string = "|" + Base64.encodeBase64String(bytes) + "|";
        String name = byteNames.get(string);
        if (name == null) {
            name = Integer.toString(byteNames.size(), 36);
            byteNames.put(string, name);
        }
        return "\"" + name + "\"-" + string;
    }

    private String digestString(DigestSha384 digest) {
        return bytesString(digest.getBytes());
    }

    public boolean isBlindlyTrusting() {
        return blindlyTrusting;
    }

    /**
     * WARNING: When this is set, the engine will report on all actions it sees,
     * signed or unsigned.
     */
    public void setBlindlyTrusting(boolean blindlyTrusting) {
        this.blindlyTrusting = blindlyTrusting;
    }

    public void addTrustedKey(DigestSha384 key) {
        trustedKeys.add(key);
    }

    public void process(final SequenceItem item) throws InvalidInputException {
        process(item, null);
    }

    // FIXME: use dynamic dispatch here
    public void process(
        final SequenceItem item,
        final DigestSha384 contextSigner)
        throws InvalidInputException {
        DigestSha384 signer = contextSigner;
        if (signer == null) {
            final DigestSha384 digest = DigestSha384.digest(item);
            signer = signedBy.get(digest);
            if (signer != null && LOG.isDebugEnabled()) {
                LOG.debug("Signed object found, signer {} signed {}",
                    digestString(signer), digestString(digest));
                LOG.debug("\n{}",
                    ConvertUtils.prettyPrint(SequenceItem.class, item));
            }
        }
        if (item instanceof Sequence) {
            doProcess((Sequence) item, signer);
        } else if (item instanceof EcdhItem) {
            doProcess((EcdhItem) item);
        } else if (item instanceof AesKey) {
            doProcess((AesKey) item);
        } else if (item instanceof AesPacket) {
            doProcess((AesPacket) item, signer);
        } else if (item instanceof Action) {
            doProcess((Action) item, signer);
        } else if (item instanceof PublicSigningKey) {
            doProcess((PublicSigningKey) item);
        } else if (item instanceof Signature) {
            doProcess((Signature) item);
        } else if (item instanceof DigestSha384) {
            doProcess((DigestSha384) item, signer);
        } else if (item instanceof PublicEncryptionKey) {
            // Do nothing - we don't currently use these
        } else if (item instanceof PassphraseProtectedKey) {
            doProcess((PassphraseProtectedKey)item);
        } else {
            // Shouldn't happen - there should be a clause here
            // for every kind of SequenceItem
            throw new RuntimeException(
                "Don't know how to process sequence item: "
                + item.getClass().getCanonicalName());
        }
    }

    public void process(final PrivateEncryptionKey privateKey) {
        final DigestSha384 keyId = privateKey.getPublicKey().getKeyId();
        LOG.debug("Adding private encryption key: {}", digestString(keyId));
        dhKeys.put(keyId, privateKey);
    }

    private void doProcess(final Sequence items, final DigestSha384 signer)
        throws InvalidInputException {
        LOG.debug("Processing sequence...");
        for (final SequenceItem item: items.sequence) {
            process(item, signer);
        }
        LOG.debug("...sequence processed.");
    }

    private void doProcess(final EcdhItem item) {
        final PrivateEncryptionKey key = dhKeys.get(item.recipient);
        if (key == null) {
            LOG.debug("Skipping encrypted packet for recipient {}",
                digestString(item.recipient));
        } else {
            LOG.debug("Processing encrypted packet for recipient {}",
                digestString(item.recipient));
            doProcess(key.getKey(item.ephemeralKey));
        }
    }

    private void doProcess(final AesKey key) {
        LOG.debug("Adding AES key id {}",
            bytesString(key.getKeyId().keyId));
        aesKeys.put(key.getKeyId(), key);
    }

    private void doProcess(final PublicSigningKey pKey) {
        final DigestSha384 keyId = pKey.getKeyId();
        LOG.debug("Adding public signing key: {}", digestString(keyId));
        dsaKeys.put(keyId, pKey);
    }

    private void doProcess(final Signature sig) throws InvalidInputException {
        final PublicSigningKey pKey = dsaKeys.get(sig.keyId);
        if (pKey == null) {
            LOG.debug("Skipping signature from unknown signer {} for {}",
                digestString(sig.keyId), digestString(sig.digest));
            return;
        }
        if (!pKey.validate(sig.digest, sig.rawSignature))
            throw new CryptographyException("Sig validation failure");
        LOG.debug("Signer {} attests to {}",
            digestString(sig.keyId), digestString(sig.digest));
        // FIXME: assert that it's not already signed?
        signedBy.put(sig.digest, sig.keyId);
    }

    private void doProcess(final Action message, final DigestSha384 signer) {
        if (LOG.isDebugEnabled()) {
            if (signer != null) {
                LOG.debug("Found message signed by {}:\n{}",
                    digestString(signer),
                    ConvertUtils.prettyPrint(Action.class, message));
            } else {
                LOG.debug("Message has no known signer:\n{}",
                    ConvertUtils.prettyPrint(Action.class, message));
            }
        }
        if (blindlyTrusting || trustedKeys.contains(signer)) {
            LOG.debug("Trusting message");
            actions.add(message.getPayload());
        }
    }

    private void doProcess(final AesPacket packet, final DigestSha384 signer) throws InvalidInputException {
        final AesKey key = aesKeys.get(packet.keyId);
        if (key != null) {
            final SequenceItem contents = key.decrypt(packet);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Decrypted packet with key {}:\n{}",
                    bytesString(packet.keyId.keyId),
                    ConvertUtils.prettyPrint(SequenceItem.class, contents));
            }
            process(contents, signer);
        } else {
            LOG.debug("Skipping packet encrypted with unknown key {}",
                bytesString(packet.keyId.keyId));
        }
    }

    private void doProcess(final DigestSha384 digest, final DigestSha384 signer) {
        if (signer != null) {
            LOG.debug("Chained signature from {} for {}",
                digestString(signer), digestString(digest));
            signedBy.put(digest, signer);
        }
    }

    private void doProcess(PassphraseProtectedKey item) {
        if (passphraseDelegate != null) {
            AesKey key = passphraseDelegate.getPassphrase(item);
            if (key != null) {
                doProcess(key);
            }
        }
    }

    public List<ActionType> getActions() {
        return actions;
    }

    public void setPassphraseDelegate(PassphraseDelegate passphraseDelegate) {
        this.passphraseDelegate = passphraseDelegate;
    }
}
