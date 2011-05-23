package net.lshift.spki.suiteb;

import net.lshift.spki.suiteb.sexpstructs.EcdsaPublicKey;
import net.lshift.spki.suiteb.sexpstructs.EcdsaSignature;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;

/**
 * A public key for verifying signatures
 */
public class PublicSigningKey
    extends PublicKey {
    private final ECDSASigner signer = new ECDSASigner();

    PublicSigningKey(CipherParameters publicKey) {
        super(publicKey);
        signer.init(false, publicKey);
    }

    public static PublicSigningKey unpack(EcdsaPublicKey sexp) {
        return new PublicSigningKey(sexp.getParameters());
    }

    @Override
    public EcdsaPublicKey pack() {
        return new EcdsaPublicKey(publicKey);
    }

    public boolean validate(DigestSha384 digest, EcdsaSignature sigVal) {
        return signer.verifySignature(digest.getBytes(),
            sigVal.r, sigVal.s);
    }
}
