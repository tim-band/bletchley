package net.lshift.spki.suiteb;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.passphrase.PassphraseProtectedKey;

/**
 * Item that can go in a sequence and so be interpreted by the InferenceEngine.
 */
@Convert.Discriminated({
    Action.class,
    AesKey.class,
    AesPacket.class,
    DigestSha384.class,
    EcdhItem.class,
    Limit.class,
    PassphraseProtectedKey.class,
    PrivateEncryptionKey.class,
    PublicEncryptionKey.class,
    PublicSigningKey.class,
    Sequence.class,
    Signature.class,
    Signed.class
})
public interface SequenceItem {
    void process(InferenceEngine engine, Condition trust)
        throws InvalidInputException;
}
