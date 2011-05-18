package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.NameBeanConvertable;
import net.lshift.spki.suiteb.EC;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * Superclass for serialization formats for EC private keys
 */
public abstract class ECPrivateKey
    extends NameBeanConvertable
{
    public final ECPublicKey publicKey;
    public final BigInteger d;

    public ECPrivateKey(ECPublicKey publicKey, BigInteger d)
    {
        super();
        this.publicKey = publicKey;
        this.d = d;
    }

    public ECPrivateKey(ECPublicKey publicKey, AsymmetricCipherKeyPair keyPair)
    {
        this(publicKey, ((ECPrivateKeyParameters)keyPair.getPrivate()).getD());
    }

    public AsymmetricCipherKeyPair getKeypair()
    {
        ECPublicKeyParameters pk = publicKey.getParameters();
        ECPrivateKeyParameters privk = new ECPrivateKeyParameters(
            d, EC.DOMAIN_PARAMETERS);
        return new AsymmetricCipherKeyPair(pk, privk);
    }

    static {
        Point.ensureRegistered();
    }
}
