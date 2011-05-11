package net.lshift.spki.suiteb;

import static net.lshift.spki.Create.list;

import java.math.BigInteger;

import net.lshift.spki.SExp;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.signers.ECDSASigner;

public class PrivateSigningKey
{
    private final AsymmetricCipherKeyPair keyPair;
    private final ECDSASigner signer = new ECDSASigner();

    private PrivateSigningKey(AsymmetricCipherKeyPair keyPair) {
        super();
        this.keyPair = keyPair;
        signer.init(true, keyPair.getPrivate());
    }

    public static PrivateSigningKey generate() {
        return new PrivateSigningKey(EC.generate());
    }

    public PublicSigningKey getPublicKey() {
        return new PublicSigningKey(keyPair.getPublic());
    }

    public SExp sign(byte[] digest)
    {
        assert digest.length == (new SHA384Digest()).getDigestSize();
        BigInteger[] signature = signer.generateSignature(digest);
        return list("suiteb-p384-ecdsa-signature",
            list("r", signature[0]),
            list("s", signature[1]));
    }
}
