package net.lshift.spki.suiteb.passphrase;

import com.google.protobuf.ByteString;
import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.AesKeyId;
import net.lshift.spki.suiteb.Condition;
import net.lshift.spki.suiteb.InferenceEngine;
import net.lshift.spki.suiteb.SequenceItem;

public class PassphraseProtectedKey implements SequenceItem {
    private final String passphraseId;
    private final byte [] salt;
    private final Integer iterations;
    private final AesKeyId keyId;

    public PassphraseProtectedKey(
            final String passphraseId, 
            final byte[] salt,
            final int iterations, 
            final AesKeyId keyId) {
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
    public void process(
            InferenceEngine engine, Condition trust) throws InvalidInputException {
        final PassphraseDelegate passphraseDelegate = engine.getPassphraseDelegate();
        if (passphraseDelegate != null) {
            final AesKey key = passphraseDelegate.getPassphrase(this);
            if (key != null) {
                engine.process(key, trust);
            }
        }
    }

    @Override
    public SuiteBProto.SequenceItem.Builder toProtobuf() {
        return SuiteBProto.SequenceItem.newBuilder().setPassphraseProtectedKey(
                SuiteBProto.PassphraseProtectedKey.newBuilder()
                .setPassphraseId(passphraseId)
                .setSalt(ByteString.copyFrom(salt))
                .setIterations(iterations)
                .setKeyId(keyId.toProtobuf()));
    }

    public static SequenceItem fromProtobuf(SuiteBProto.PassphraseProtectedKey passphraseProtectedKey) {
        return new PassphraseProtectedKey(
                passphraseProtectedKey.getPassphraseId(),
                passphraseProtectedKey.getSalt().toByteArray(),
                passphraseProtectedKey.getIterations(),
                AesKeyId.fromProtobuf(passphraseProtectedKey.getKeyId()));
    }

}
