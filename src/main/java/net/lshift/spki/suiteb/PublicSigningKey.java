package net.lshift.spki.suiteb;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.bletchley.suiteb.proto.SuiteBProto.EcPoint;
import net.lshift.bletchley.suiteb.proto.SuiteBProto.SequenceItem.Builder;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.suiteb.proto.ProtobufHelper;
import net.lshift.spki.suiteb.sexpstructs.EcdsaPublicKey;
import net.lshift.spki.suiteb.sexpstructs.EcdsaSignature;

/**
 * A public key for verifying signatures
 */
public class PublicSigningKey
    extends PublicKey
    implements SequenceItem {
    private final ECDSASigner signer = new ECDSASigner();

    PublicSigningKey(final CipherParameters publicKey) {
        super(publicKey);
        signer.init(false, publicKey);
    }

    public boolean validate(final DigestSha384 digest, final EcdsaSignature sigVal) {
        return signer.verifySignature(digest.getBytes(), sigVal.r, sigVal.s);
    }

    @Override
    public void process(final InferenceEngine engine, final Condition trust)
        throws InvalidInputException {
        engine.addPublicSigningKey(this);
        engine.addItemTrust(keyId, trust);
    }

    public static PublicSigningKey fromProtobuf(SuiteBProto.PublicSigningKey publicSigningKey) 
    throws CryptographyException {
        return fromProtobuf(publicSigningKey.getPoint());
    }

    public static PublicSigningKey fromProtobuf(EcPoint point) throws CryptographyException {
        return new PublicSigningKey(Ec.toECPublicKeyParameters(ProtobufHelper.ecPointFromProtobuf(point)));
    }

    @Override
    public Builder toProtobuf() {
        return SuiteBProto.SequenceItem.newBuilder()
                .setPublicSigningKey(SuiteBProto.PublicSigningKey.newBuilder()
                .setPoint(new EcdsaPublicKey(this.publicKey).toProtobuf()));
    }

}
