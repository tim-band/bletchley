package net.lshift.spki.suiteb;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.suiteb.fingerprint.FingerprintUtils;
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
    private final Map<DigestSha384, Condition> trustedItems
        = new HashMap<DigestSha384, Condition>();
    private final Map<DigestSha384, Condition> trustedKeys
        = new HashMap<DigestSha384, Condition>();
    private final List<ActionType> actions
        = new ArrayList<ActionType>();

    private final Map<String, String> byteNames = new HashMap<String,String>();

    private PassphraseDelegate passphraseDelegate;

    private Date time;

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

    public void process(final SequenceItem item) throws InvalidInputException {
        process(item, new OrCondition());
    }

    public void processTrusted(final SequenceItem item) throws InvalidInputException {
        process(item, new AndCondition());
    }

    // FIXME: use dynamic dispatch here
    protected void process(
        final SequenceItem item,
        final Condition trusted)
        throws InvalidInputException {
        if (item instanceof Action) {
            doProcess((Action) item, trusted);
        } else if (item instanceof AesKey) {
            doProcess((AesKey) item);
        } else if (item instanceof AesPacket) {
            doProcess((AesPacket) item, trusted);
        } else if (item instanceof Cert) {
            doProcess((Cert) item, trusted);
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

    private void doProcess(final Action message, final Condition trusted) {
        boolean allow = trusted.allows(this, message.getPayload());
        if (LOG.isDebugEnabled()) {
            if (allow) {
                LOG.debug("Trusting action:\n{}",
                    ConvertUtils.prettyPrint(Action.class, message));
            } else {
                LOG.debug("Discarding untrusted action:\n{}",
                    ConvertUtils.prettyPrint(Action.class, message));
            }
        }
        if (allow) {
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

    private void doProcess(final AesPacket packet, final Condition trusted) throws InvalidInputException {
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

    private void doProcess(Cert cert, Condition trusted) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Found cert, trusted {} {}",
                trusted, digestString(cert.subject));
        }
        orPut(trustedKeys, cert.subject,
            new AndCondition(trusted, cert.getCondition()));
    }

    private void doProcess(final DigestSha384 digest, final Condition trusted) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Chaining trust {} for {}",
                trusted, digestString(digest));
        }
        orPut(trustedItems, digest, trusted);
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

    private void doProcess(final Sequence items, final Condition trusted)
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
        if (!trustedKeys.containsKey(sig.keyId)) {
            LOG.debug("Key is unknown");
        } else {
            orPut(trustedItems, sig.digest, trustedKeys.get(sig.keyId));
        }
    }

    private void doProcess(Signed signed) throws InvalidInputException {
        if (!DigestSha384.DIGEST_NAME.equals(signed.hashType)) {
            throw new CryptographyException(
                "Unknown hash type: " + signed.hashType);
        }
        final DigestSha384 digest = DigestSha384.digest(signed.payload);
        Condition trusted = trustedItems.get(digest);
        if (LOG.isDebugEnabled()) {
            if (trusted != null) {
                LOG.debug("Trusted object {} {}", trusted, digestString(digest));
            } else {
                LOG.debug("Signed object with no signer, ignoring {}",
                    digestString(digest));
            }
            LOG.debug("\n{}",
                ConvertUtils.prettyPrint(SequenceItem.class, signed.payload));
        }
        if (trusted != null) {
            process(signed.payload, trusted);
        }
    }

    private void orPut(
        Map<DigestSha384, Condition> map,
        DigestSha384 subject,
        Condition condition) {
        map.put(subject, new OrCondition(condition, map.get(subject)));
    }

    public List<ActionType> getActions() {
        return actions;
    }

    public void setPassphraseDelegate(final PassphraseDelegate passphraseDelegate) {
        this.passphraseDelegate = passphraseDelegate;
    }

    public Date getTime() {
        return time;
    }

    public void setTime(Date time) {
        if (this.time != null)
            throw new IllegalStateException("Time can only be set once");
        this.time = time;
    }

    public void setTime() {
        if (this.time != null)
            throw new IllegalStateException("Time can only be set once");
        this.time = new Date();
    }
}
