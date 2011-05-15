package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.NameBeanConvertable;
import net.lshift.spki.suiteb.EC;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

public class ECPrivateKey
    extends NameBeanConvertable
{
    protected final ECPublicKey publicKey;
    protected final BigInteger d;

    public ECPrivateKey(ECPublicKey publicKey, BigInteger d)
    {
        super();
        this.publicKey = publicKey;
        this.d = d;
    }

    public ECPublicKey getPublicKey()
    {
        return publicKey;
    }

    public BigInteger getD()
    {
        return d;
    }

    public AsymmetricCipherKeyPair getKeypair()
    {
        ECPublicKeyParameters pk = publicKey.getParameters();
        ECPrivateKeyParameters privk = new ECPrivateKeyParameters(
            d, EC.DOMAIN_PARAMETERS);
        return new AsymmetricCipherKeyPair(pk, privk);
    }
}
