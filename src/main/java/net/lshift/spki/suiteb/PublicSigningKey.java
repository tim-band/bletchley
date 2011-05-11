package net.lshift.spki.suiteb;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;

import net.lshift.spki.Get;
import net.lshift.spki.SExp;

public class PublicSigningKey
{
    private ECPublicKeyParameters publicKey;
    private final ECDSASigner signer = new ECDSASigner();

    PublicSigningKey(CipherParameters publicKey) {
        this.publicKey = (ECPublicKeyParameters) publicKey;
        signer.init(false, publicKey);
    }

    public SExp toSExp() {
        return EC.toSExpDSA(publicKey);
    }

    public static PublicSigningKey fromSExp(SExp sexp) {
        return new PublicSigningKey(EC.toECPublicKeyParameters(sexp));
    }

    public boolean validate(byte[] digest, SExp sigVal)
    {
        return signer.verifySignature(digest,
            Get.getBigInteger("r", sigVal),
            Get.getBigInteger("s", sigVal));
    }
}
