package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.AesPacket;
import net.lshift.spki.suiteb.DigestSha384;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.PublicSigningKey;
import net.lshift.spki.suiteb.Signature;

/**
 * Item that can go in a sequence and so be interpreted by the InferenceEngine.
 */
@Convert.Discriminated({
    PublicEncryptionKey.class,
    AesPacket.class,
    AesKey.class,
    EcdhItem.class,
    SimpleMessage.class,
    PublicSigningKey.class,
    Signature.class,
    DigestSha384.class,
    Sequence.class})
public interface SequenceItem {
    // Marker interface, no body
}
