package net.lshift.spki.suiteb;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;

import org.bouncycastle.crypto.signers.StandardDSAEncoding;

import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.suiteb.sexpstructs.ECPointConverter;
import net.lshift.spki.suiteb.sexpstructs.EcdsaSignature;

/**
 * Import Bletchley objects from other cryptography frameworks.
 * This is mostly motivated by a need to import with Android Keystore
 * @author david
 *
 */
public class Jca {
    private Jca() {
        // This class cannot be instantiated
    }
    
    /**
     * Convert a JCA ECPublicKey to a Bletchley public signing key,
     * only if the point is valid on Bletchley's EC curve.
     * It's up to you to ensure this is a signing key, since the JCA doesn't
     * make the distinction.
     * Note: this relies on {@link ECPointConverter#convert} rejecting invalid points,
     * rather than on checking that the curve in key matches the Bletchley EC curve.
     * This is unfriendly because it doesn't give a clear message.
     * @param key the key to convert
     * @return the Bletchley public key
     * @throws CryptographyException if the point we obtain from the key
     * is not on Bletchley's EC curve.
     */
    public static PublicSigningKey importPublicSigningKey(ECPublicKey key) 
    throws CryptographyException {
        // Note this relies on ECPointConverter.convert rejecting invalid points,
        // rather than on checking that the curve in key is the right curve
        // I guess there might be points that belong to multiple curves and then 
        // the conversion will work, but signatures won't validate, but the chance 
        // of such a point being generated in testing is very small
        return new PublicSigningKey(Ec.toECPublicKeyParameters(
                ECPointConverter.convert(key.getW().getAffineX(), key.getW().getAffineY())));
    }

    public static PublicSigningKey importPublicSigningKey(PublicKey publicKey) throws CryptographyException {
        if(publicKey instanceof ECPublicKey) {
            return importPublicSigningKey((ECPublicKey)publicKey);
        } else {
            throw new IllegalArgumentException("publicKey must be an instance of ECPublicKey");
        }
    }
    
    /**
     * Convert an ASN.1. DER encoded signature to a Bletchley Signature. Bletchley
     * Signature includes enough meta data to make it a useful stanza in a message
     * the key used to make the signature, and the digest which is signed. This is quite
     * unnatural if you use {@link java.security#Signature} doesn't even
     * provide a way to sign a digest. The signature must be SHA384withECDSA
     * @param key used in the signing request
     * @param digest the digest which was signed
     * @param signature the bytes of the signature, DER-encoded ASN.1
     * @return the signature
     */
    public static Signature importSignature(
            DigestSha384 digest,
            PublicSigningKey key,
            byte [] signature) {
        try {
            BigInteger [] values = StandardDSAEncoding.INSTANCE.decode(Ec.DOMAIN_PARAMETERS.getN(), signature);
            return new Signature(
                    digest, 
                    key.getKeyId(), 
                    new EcdsaSignature(values[0], values[1]));
        } catch (IOException e) {
            throw new AssertionError("There's no IO happenning here", e);
        }
    }

    /**
     * This is a higher level interface for signing using JCA. The point of offering
     * this is so that you can use the fingerprint reader in and Android phone to
     * sign something. I.e. Use a key pair stored in the TEE. You might also want to
     * sign things using a PKCS#11 provider.
     * This method is quite inefficient: it serialises the payload and digests it
     * twice, because JCA won't just encrypt a digest: you have to sign the actual
     * data.
     * @param keyPair the JCA key pair used in signing
     * @param payload the payload to sign
     * @return a sequence containing the signature and signed payload
     * @throws CryptographyException
     */
    public static SequenceItem signed(KeyPair keyPair, SequenceItem payload)
        throws CryptographyException {
        try {
            java.security.Signature signature = java.security.Signature.getInstance("SHA384withECDSA");
            signature.initSign(keyPair.getPrivate());
            // This serialises the payload and generates the digest twice: once here in signature.update
            // and then again in DigestSha384.digest(payload) below. I can do slighly better than
            // this but can't figure out a way to avoid it completely, so I'm just going to ignore
            // it for now.
            signature.update(ConvertUtils.toBytes(payload));
            return SequenceUtils.sequence(
                    importSignature(
                            DigestSha384.digest(payload), 
                            importPublicSigningKey(keyPair.getPublic()),
                            signature.sign()), 
                    Signed.signed(payload));
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
            throw new CryptographyException("JCA exception during signing", e);
        }
    }
}
