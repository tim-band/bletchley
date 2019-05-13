package net.lshift.spki.suiteb;

import java.io.IOException;
import java.io.OutputStream;
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
 * Import Bletchley objects from JCA.
 * Unlike Bletchley in general, a JCA provider must be configured to
 * use this module.
 * This is mostly motivated by a need to use signatures generated
 * by keys protected by Androids TEE, although it has other uses.
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
     * Convert an ASN.1. DER encoded signature to a Bletchley Signature.
     * @see Signature#Signature(DigestSha384, DigestSha384, EcdsaSignature)
     * @param key used in the signing request, so we can attach the key id as meta data
     * @param digest the digest which was signed, so we can attach it as meta data
     * @param signature the bytes of the signature, DER-encoded ASN.1. The signature must be SHA384withECDSA.
     * @return the signature
     */
    private static Signature importSignature(
            DigestSha384 digest,
            PublicSigningKey key,
            byte [] signature) {
        try {
            BigInteger [] values = StandardDSAEncoding.INSTANCE.decode(
                    Ec.DOMAIN_PARAMETERS.getN(), signature);
            return new Signature(
                    digest,
                    key.getKeyId(),
                    new EcdsaSignature(values[0], values[1]));
        } catch (IOException e) {
            throw new AssertionError("There's no IO happenning here", e);
        }
    }

    private static class SignatureIOException extends IOException {
        private static final long serialVersionUID = 1L;
        public SignatureIOException(SignatureException e) {
            super(e);
        }
    }

    /**
     * This class represents a signing session. See {@link #signer(KeyPair,SequenceItem}
     */
    public static class Signer {
        public final PublicSigningKey publicKey;
        public final SequenceItem payload;
        public final java.security.Signature signature;

        private Signer(KeyPair keyPair, SequenceItem payload) throws CryptographyException {
            this.publicKey = importPublicSigningKey(keyPair.getPublic());
            this.payload = payload;
            try {
                signature = java.security.Signature.getInstance("SHA384withECDSA");
                signature.initSign(keyPair.getPrivate());
            } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                throw new CryptographyException("JCA provider not compatible", e);
            }
        }

        private void importPayload(SequenceItem payload) throws CryptographyException {
            try {
                ConvertUtils.write(payload, new OutputStream() {
                    @Override public void write(int b) throws IOException {
                        try {
                            signature.update((byte)b);
                        } catch (SignatureException e) {
                            throw new SignatureIOException(e);
                        }
                    }

                    @Override public void write(byte[] data, int off, int len) throws IOException {
                        try {
                            signature.update(data, off, len);
                        } catch (SignatureException e) {
                            throw new SignatureIOException(e);
                        }
                    }
                });
            }  catch(SignatureIOException e) {
                throw new CryptographyException("JCA exception during signing",e.getCause());
            } catch (IOException e) {
                throw new AssertionError(e);
            }
        }

        public SequenceItem signed() throws CryptographyException {
            try {
                importPayload(payload);
                return SequenceUtils.sequence(
                        importSignature(
                                DigestSha384.digest(this.payload),
                                this.publicKey,
                                signature.sign()),
                        Signed.signed(this.payload));
            } catch (SignatureException e) {
                throw new CryptographyException("JCA exception during signing", e);
            }
        }
    }

    /**
     * Create a signed sequence, where key use requires authentication.
     * The signed sequence creates the forward chain that assigns the trust of the key to the payload.
     * This can, for example, be used with Android's JCA environment for keys
     * which are stored in the TEE with userAuthenticationRequired set to true. You might
     * also want to a key held by a PKCS#11 provider.
     * @param keyPair the JCA key pair used in signing
     * @param payload the payload to sign
     * @return a sequence containing the signature and signed payload
     * @throws CryptographyException for a range of issues, which are generally that the JCA
     *   provider doesn't support the primitives provided by Bletchley.
     */
    public static Signer signer(KeyPair keyPair, SequenceItem payload)
        throws CryptographyException {
        return new Signer(keyPair, payload);
    }

    /**
     * Equivalent to {@link #signer(KeyPair, SequenceItem)} and {@link Signer#signed()}.
     */
    public static SequenceItem signed(KeyPair keyPair, SequenceItem payload)
        throws CryptographyException {
        return signer(keyPair, payload).signed();
    }
}
