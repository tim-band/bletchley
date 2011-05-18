package net.lshift.spki.suiteb;

import java.util.List;

import net.lshift.spki.convert.PackConvertable;
import net.lshift.spki.suiteb.sexpstructs.ECDHItem;
import net.lshift.spki.suiteb.sexpstructs.ECDHPublicKey;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * A public key for encrypting data.
 */
public class PublicEncryptionKey extends PackConvertable  {
    private final ECPublicKeyParameters publicKey;
    private final DigestSha384 keyId;

    PublicEncryptionKey(CipherParameters publicKey) {
        this.publicKey = (ECPublicKeyParameters) publicKey;
        keyId = DigestSha384.digest(
            PublicEncryptionKey.class, this);
    }

    public DigestSha384 getKeyId()
    {
        return keyId;
    }

    public static PublicEncryptionKey unpack(ECDHPublicKey sexp) {
        return new PublicEncryptionKey(sexp.getParameters());
    }

    @Override
    public ECDHPublicKey pack() {
        return new ECDHPublicKey(publicKey);
    }

    public AESKey setupEncrypt(List<SequenceItem> sequence)
    {
        AsymmetricCipherKeyPair ephemeralKey = EC.generate();
        AESKey res = new AESKey(EC.generateAESKeyId(),
            EC.sessionKey(
                publicKey,
                ephemeralKey.getPublic(),
                ephemeralKey.getPrivate(),
                publicKey));
        sequence.add(new ECDHItem(
            keyId, res.keyId,
            ((ECPublicKeyParameters) ephemeralKey.getPublic()).getQ()));
        return res;
    }
}
