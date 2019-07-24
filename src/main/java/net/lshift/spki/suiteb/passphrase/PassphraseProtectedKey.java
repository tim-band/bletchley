package net.lshift.spki.suiteb.passphrase;

import com.google.protobuf.Message;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.AesKeyId;
import net.lshift.spki.suiteb.Condition;
import net.lshift.spki.suiteb.InferenceEngine;
import net.lshift.spki.suiteb.SequenceItem;

@Convert.ByPosition(name="passphrase-protected-key",
    fields={"passphraseId", "salt", "iterations", "keyId"})
public class PassphraseProtectedKey implements SequenceItem {
    private final String passphraseId;
    private final byte [] salt;
    private final Integer iterations;
    private final AesKeyId keyId;

    public PassphraseProtectedKey(final String passphraseId, final byte[] salt,
                                  final int iterations, final AesKeyId keyId) {
        this.passphraseId = passphraseId;
        this.salt = salt;
        this.iterations = iterations;
        this.keyId = keyId;
    }

    public String getPassphraseId() {
        return passphraseId;
    }

    public byte[] getSalt() {
        return salt;
    }

    public int getIterations() {
        return iterations;
    }

    public AesKeyId getKeyId() {
        return keyId;
    }

    public AesKey getKey(final String passphrase) {
        final AesKey res = PassphraseUtils.getKey(
            passphraseId, salt, iterations, passphrase);
        if (!keyId.equals(res.getKeyId())) {
                return null;
        }
        return res;
    }

    @Override
    public <ActionType extends Message> void process(
            InferenceEngine<ActionType> engine, Condition trust,
            Class<ActionType> actionType) throws InvalidInputException {
        final PassphraseDelegate passphraseDelegate = engine.getPassphraseDelegate();
        if (passphraseDelegate != null) {
            final AesKey key = passphraseDelegate.getPassphrase(this);
            if (key != null) {
                engine.process(key, trust);
            }
        }
    }

    @Override
    public SuiteBProto.SequenceItem.Builder toProtobufSequenceItem() {
        throw new UnsupportedOperationException("Passphrase protected keys are not yet defined in the protocol buffer schema");
    }

}
