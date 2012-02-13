package net.lshift.spki.suiteb;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.suiteb.fingerprint.FingerprintUtils;
import net.lshift.spki.suiteb.passphrase.PassphraseDelegate;
import net.lshift.spki.suiteb.passphrase.PassphraseProtectedKey;
import net.lshift.spki.suiteb.sexpstructs.EcdhItem;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.sexpstructs.Signed;

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
    private final Set<DigestSha384> trustedItems
        = new HashSet<DigestSha384>();

    private final Set<DigestSha384> trustedKeys
        = new HashSet<DigestSha384>();
    private final List<ActionType> actions
        = new ArrayList<ActionType>();

    private final Map<String, String> byteNames = new HashMap<String,String>();

    private PassphraseDelegate passphraseDelegate;

    private String namedString(final String string) {
        String name = byteNames.get(string);
        if (name == null) {
            name = Integer.toString(byteNames.size(), 36);
            byteNames.put(string, name);
        }
        return "" + name + ":" + string;
    }

    private String bytesString(final byte[] bytes) {
        final String string = "|" + Base64.encodeBase64String(bytes) + "|";
        return namedString(string);
    }

    private String digestString(final DigestSha384 digest) {
        return namedString(FingerprintUtils.getFingerprint(digest));
    }

    public void addTrustedKey(final DigestSha384 key) {
        trustedKeys.add(key);
    }

    public void process(final SequenceItem item) throws InvalidInputException {
        process(item, false);
    }

    public void processTrusted(final SequenceItem item) throws InvalidInputException {
        process(item, true);
    }

    // FIXME: use dynamic dispatch here
    protected void process(
        final SequenceItem item,
        final boolean trusted)
        throws InvalidInputException {
        if (item instanceof Action) {
            doProcess((Action) item, trusted);
        } else if (item instanceof AesKey) {
            doProcess((AesKey) item);
        } else if (item instanceof AesPacket) {
            doProcess((AesPacket) item, trusted);
        } else if (item instanceof DigestSha384) {
            doProcess((DigestSha384) item, trusted);
        } else if (item instanceof EcdhItem) {
            doProcess((EcdhItem) item);
        } else if (item instanceof PassphraseProtectedKey) {
            doProcess((PassphraseProtectedKey)item);
        } else if (item instanceof PrivateEncryptionKey) {
            doProcess((PrivateEncryptionKey)item);
        } else if (item instanceof PublicSigningKey) {
            doProcess((PublicSigningKey) item);
        } else if (item instanceof Sequence) {
            doProcess((Sequence) item, trusted);
        } else if (item instanceof Signature) {
            doProcess((Signature) item);
        } else if (item instanceof Signed) {
            doProcess((Signed) item);
        } else {
            // Shouldn't happen - there should be a clause here
            // for every kind of SequenceItem
            throw new RuntimeException(
                "Don't know how to process sequence item: "
                + item.getClass().getCanonicalName());
        }
    }

    private void doProcess(final Action message, final boolean trusted) {
        if (LOG.isDebugEnabled()) {
            if (trusted) {
                LOG.debug("Trusting action:\n{}",
                    ConvertUtils.prettyPrint(Action.class, message));
            } else {
                LOG.debug("Discarding untrusted action:\n{}",
                    ConvertUtils.prettyPrint(Action.class, message));
            }
        }
        if (trusted) {
            LOG.debug("Trusting message");
            actions.add(message.getPayload());
        }
    }

    private void doProcess(final AesKey key) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Adding AES key id {}",
                bytesString(key.getKeyId().keyId));
        }
        aesKeys.put(key.getKeyId(), key);
    }

    private void doProcess(final AesPacket packet, final boolean trusted) throws InvalidInputException {
        final AesKey key = aesKeys.get(packet.keyId);
        if (key != null) {
            final SequenceItem contents = key.decrypt(packet);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Decrypted packet with key {}:\n{}",
                    bytesString(packet.keyId.keyId),
                    ConvertUtils.prettyPrint(SequenceItem.class, contents));
            }
            process(contents, trusted);
        } else {
            LOG.debug("Skipping packet encrypted with unknown key {}",
                bytesString(packet.keyId.keyId));
        }
    }

    private void doProcess(final DigestSha384 digest, final boolean trusted) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Chaining trust {} for {}",
                trusted, digestString(digest));
        }
        if (trusted) {
            trustedItems.add(digest);
        }
    }

    private void doProcess(final EcdhItem item) {
        final PrivateEncryptionKey key = dhKeys.get(item.recipient);
        if (key == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Skipping encrypted packet for recipient {}",
                    digestString(item.recipient));
            }
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Processing encrypted packet for recipient {}",
                    digestString(item.recipient));
            }
            doProcess(key.getKey(item.ephemeralKey));
        }
    }

    private void doProcess(final PassphraseProtectedKey item) {
        if (passphraseDelegate != null) {
            final AesKey key = passphraseDelegate.getPassphrase(item);
            if (key != null) {
                doProcess(key);
            }
        }
    }

    private void doProcess(final PrivateEncryptionKey privateKey) {
        final DigestSha384 keyId = privateKey.getPublicKey().getKeyId();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Adding private encryption key: {}", digestString(keyId));
        }
        dhKeys.put(keyId, privateKey);
    }

    private void doProcess(final PublicSigningKey pKey) {
        final DigestSha384 keyId = pKey.getKeyId();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Adding public signing key: {}", digestString(keyId));
        }
        dsaKeys.put(keyId, pKey);
    }

    private void doProcess(final Sequence items, final boolean trusted)
        throws InvalidInputException {
        LOG.debug("Processing sequence...");
        for (final SequenceItem item: items.sequence) {
            process(item, trusted);
        }
        LOG.debug("...sequence processed.");
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
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signer {} attests to {}",
                digestString(sig.keyId), digestString(sig.digest));
        }
        if (trustedKeys.contains(sig.keyId)) {
            LOG.debug("Key is trusted");
            trustedItems.add(sig.digest);
        } else {
            LOG.debug("Key is not trusted");
        }
    }

    private void doProcess(Signed signed) throws InvalidInputException {
        if (!DigestSha384.DIGEST_NAME.equals(signed.hashType)) {
            throw new CryptographyException(
                "Unknown hash type: " + signed.hashType);
        }
        final DigestSha384 digest = DigestSha384.digest(signed.payload);
        boolean trusted = trustedItems.contains(digest);
        if (LOG.isDebugEnabled()) {
            if (trusted) {
                LOG.debug("Trusted object {}", digestString(digest));
            } else {
                LOG.debug("Signed object with no signer, ignoring {}",
                    digestString(digest));
            }
            LOG.debug("\n{}",
                ConvertUtils.prettyPrint(SequenceItem.class, signed.payload));
        }
        if (trusted) {
            process(signed.payload, true);
        }
    }

    public List<ActionType> getActions() {
        return actions;
    }

    public void setPassphraseDelegate(final PassphraseDelegate passphraseDelegate) {
        this.passphraseDelegate = passphraseDelegate;
    }
}
