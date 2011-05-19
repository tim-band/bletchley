package net.lshift.spki.suiteb;

import java.util.List;

import net.lshift.spki.suiteb.sexpstructs.ECDHItem;
import net.lshift.spki.suiteb.sexpstructs.ECDHPublicKey;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * A public key for encrypting data.
 */
public class PublicEncryptionKey extends PublicKey  {
    PublicEncryptionKey(CipherParameters publicKey) {
        super(publicKey);
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
        AESKey res = new AESKey(
            EC.sessionKey(
                publicKey,
                ephemeralKey.getPublic(),
                ephemeralKey.getPrivate(),
                publicKey));
        sequence.add(new ECDHItem(
            keyId,
            ((ECPublicKeyParameters) ephemeralKey.getPublic()).getQ()));
        return res;
    }
}
