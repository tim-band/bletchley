package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.ConditionJoiner.or;
import static net.lshift.spki.suiteb.UntrustedCondition.nullMeansUntrusted;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.suiteb.passphrase.PassphraseDelegate;

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

    private final List<ActionType> actions
        = new ArrayList<ActionType>();

    private final Map<DigestSha384, Condition> itemTrust
        = new HashMap<DigestSha384, Condition>();

    private final Map<DigestSha384, PublicEncryptionKey> publicEncryptionKeys
    = new HashMap<DigestSha384, PublicEncryptionKey>();
    private final Map<DigestSha384, PrivateEncryptionKey> privateEncryptionKeys
        = new HashMap<DigestSha384, PrivateEncryptionKey>();
    private final Map<DigestSha384, PublicSigningKey> publicSigningKeys
        = new HashMap<DigestSha384, PublicSigningKey>();
    private final Map<AesKeyId, AesKey> aesKeys
        = new HashMap<AesKeyId, AesKey>();

    private final Map<InferenceVariable<?>, Object> variables
        = new HashMap<InferenceVariable<?>, Object>();

    private PassphraseDelegate passphraseDelegate;

//    private final Map<String, String> byteNames = new HashMap<String,String>();
//
//    private String namedString(final String string) {
//        String name = byteNames.get(string);
//        if (name == null) {
//            name = Integer.toString(byteNames.size(), 36);
//            byteNames.put(string, name);
//        }
//        return "" + name + ":" + string;
//    }
//
//    public String bytesString(final byte[] bytes) {
//        final String string = "|" + Base64.encodeBase64String(bytes) + "|";
//        return namedString(string);
//    }
//
//    private String digestString(final DigestSha384 digest) {
//        return namedString(FingerprintUtils.getFingerprint(digest));
//    }

    public void process(final SequenceItem item) throws InvalidInputException {
        process(item, UntrustedCondition.UNTRUSTED);
    }

    public void processTrusted(final SequenceItem item) throws InvalidInputException {
        process(item, TrustedCondition.TRUSTED);
    }

    public void process(final SequenceItem item, final Condition trust) throws InvalidInputException {
        LOG.debug("Processing item:\n{}",
            ConvertUtils.prettyPrint(item));
        item.process(this, trust);
    }

    public List<ActionType> getActions() {
        return actions;
    }

    public ActionType getSoleAction() throws CryptographyException {
        if (actions.size() == 1) {
            return actions.get(0);
        } else if (actions.isEmpty()) {
            throw new CryptographyException("No validated actions found");
        } else {
            throw new CryptographyException(
                    "Expected exactly one validated action, found: " + actions);
        }
    }

    public void addAction(final ActionType payload) {
        actions.add(payload);
    }

    public Condition getItemTrust(final DigestSha384 digest) {
        return nullMeansUntrusted(itemTrust.get(digest));
    }

    public void addItemTrust(final DigestSha384 digest, final Condition condition) {
        itemTrust.put(digest, or(condition, getItemTrust(digest)));
    }

    public PublicEncryptionKey getPublicEncryptionKey(final DigestSha384 recipient) {
        return publicEncryptionKeys.get(recipient);
    }

    public void addPublicEncryptionKey(
        final PublicEncryptionKey key) {
        publicEncryptionKeys.put(key.getKeyId(), key);
    }

    public PrivateEncryptionKey getPrivateEncryptionKey(final DigestSha384 recipient) {
        return privateEncryptionKeys.get(recipient);
    }

    public void addPrivateEncryptionKey(
        final PrivateEncryptionKey key) {
        final PublicEncryptionKey publicKey = key.getPublicKey();
        final DigestSha384 keyId = publicKey.getKeyId();
        privateEncryptionKeys.put(keyId, key);
        publicEncryptionKeys.put(keyId, publicKey);
    }

    public PublicSigningKey getPublicSigningKey(final DigestSha384 keyId) {
        return publicSigningKeys.get(keyId);
    }

    public void addPublicSigningKey(final PublicSigningKey key) {
        publicSigningKeys.put(key.getKeyId(), key);
    }

    public AesKey getAesKey(final AesKeyId keyId) {
        return aesKeys.get(keyId);
    }

    public void addAesKey(final AesKey key) {
        aesKeys.put(key.getKeyId(), key);
    }

    public PassphraseDelegate getPassphraseDelegate() {
        return passphraseDelegate;
    }

    public void setPassphraseDelegate(final PassphraseDelegate passphraseDelegate) {
        this.passphraseDelegate = passphraseDelegate;
    }

    public Object getVar(final InferenceVariable<?> v) {
        final Object res = variables.get(v);
        if (res == null) {
            throw new IllegalStateException(
                "Variable not set on InferenceEngine:" + v.toString());
        }
        return res;
    }

    public void setVar(final InferenceVariable<?> v, final Object val) {
        if (val == null) {
            throw new NullPointerException(
                "Cannot set null value on variable: " + v);
        }
        if (variables.containsKey(v)) {
            throw new IllegalStateException(
                "Variable can only be set once:" + v.toString());
        }
        variables.put(v, val);
    }
}
