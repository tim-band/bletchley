package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.AesPacket;
import net.lshift.spki.suiteb.Cert;
import net.lshift.spki.suiteb.DigestSha384;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PublicSigningKey;
import net.lshift.spki.suiteb.Signature;
import net.lshift.spki.suiteb.Signed;
import net.lshift.spki.suiteb.passphrase.PassphraseProtectedKey;

/**
 * Item that can go in a sequence and so be interpreted by the InferenceEngine.
 */
@Convert.Discriminated({
    Action.class,
    AesKey.class,
    AesPacket.class,
    Cert.class,
    DigestSha384.class,
    EcdhItem.class,
    PassphraseProtectedKey.class,
    PrivateEncryptionKey.class,
    PublicSigningKey.class,
    Sequence.class,
    Signature.class,
    Signed.class
})
public interface SequenceItem {
    // Marker interface, no body
}
