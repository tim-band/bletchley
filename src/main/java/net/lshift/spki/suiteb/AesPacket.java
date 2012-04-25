package net.lshift.spki.suiteb;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.SexpBacked;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A SequenceItem encrypted with AES/GCM.
 */
@Convert.ByPosition(name = "aes-gcm-encrypted",
fields={"keyId", "nonce", "ciphertext"})
public class AesPacket extends SexpBacked implements SequenceItem {
    private static final Logger LOG
    = LoggerFactory.getLogger(AesPacket.class);

    public final AesKeyId keyId;
    public final byte[] nonce;
    public final byte[] ciphertext;

    public AesPacket(
        final AesKeyId keyId,
        final byte[] nonce,
        final byte[] ciphertext
                    ) {
        super();
        this.keyId = keyId;
        this.nonce = nonce;
        this.ciphertext = ciphertext;
    }

    @Override
    public void process(final InferenceEngine engine, final Condition trust)
                    throws InvalidInputException {
        final AesKey key = engine.getAesKey(keyId);
        if (key != null) {
            final SequenceItem contents = key.decrypt(this);
            LOG.debug("Decryption successful");
            engine.process(contents, trust);
        } else {
            LOG.debug("Key not known");
        }
    }
}
