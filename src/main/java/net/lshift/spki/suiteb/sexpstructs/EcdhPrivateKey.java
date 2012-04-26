package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.PublicEncryptionKey;

/**
 * Serialization format for private encryption keys
 */
@Convert.ByName("suiteb-p384-ecdh-private-key")
public class EcdhPrivateKey {
    public final PublicEncryptionKey publicKey;
    public final BigInteger d;

    public EcdhPrivateKey(final PublicEncryptionKey publicKey, final BigInteger d) {
        super();
        this.publicKey = publicKey;
        this.d = d;
    }
}
