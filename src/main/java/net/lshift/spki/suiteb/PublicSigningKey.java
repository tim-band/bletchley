package net.lshift.spki.suiteb;

import net.lshift.spki.suiteb.sexpstructs.ECDSAPublicKey;
import net.lshift.spki.suiteb.sexpstructs.ECDSASignature;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;

/**
 * A public key for verifying signatures
 */
public class PublicSigningKey extends PublicKey
{
    private final ECDSASigner signer = new ECDSASigner();

    PublicSigningKey(CipherParameters publicKey) {
        super(publicKey);
        signer.init(false, publicKey);
    }

    public static PublicSigningKey unpack(ECDSAPublicKey sexp) {
        return new PublicSigningKey(sexp.getParameters());
    }

    @Override
    public ECDSAPublicKey pack() {
        return new ECDSAPublicKey(publicKey);
    }

    public boolean validate(DigestSha384 digest, ECDSASignature sigVal)
    {
        return signer.verifySignature(digest.getBytes(),
            sigVal.r, sigVal.s);
    }
}
