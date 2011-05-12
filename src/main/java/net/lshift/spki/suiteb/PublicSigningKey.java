package net.lshift.spki.suiteb;

import net.lshift.spki.suiteb.sexpstructs.ECDSAPublicKey;
import net.lshift.spki.suiteb.sexpstructs.ECDSASignature;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;

public class PublicSigningKey
{
    private ECPublicKeyParameters publicKey;
    private final ECDSASigner signer = new ECDSASigner();

    PublicSigningKey(CipherParameters publicKey) {
        this.publicKey = (ECPublicKeyParameters) publicKey;
        signer.init(false, publicKey);
    }

    public static PublicSigningKey unpack(ECDSAPublicKey sexp) {
        return new PublicSigningKey(EC.toECPublicKeyParameters(sexp));
    }

    public ECDSAPublicKey pack() {
        return EC.toECDSAPublicKey(publicKey);
    }

    public boolean validate(DigestSha384 digest, ECDSASignature sigVal)
    {
        return signer.verifySignature(digest.getBytes(),
            sigVal.getR(), sigVal.getS());
    }
}
