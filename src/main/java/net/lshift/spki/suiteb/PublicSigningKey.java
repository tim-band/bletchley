package net.lshift.spki.suiteb;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.bletchley.suiteb.proto.SuiteBProto.EcPoint;
import net.lshift.bletchley.suiteb.proto.SuiteBProto.SequenceItem.Builder;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.convert.Convert.ConvertClass;
import net.lshift.spki.convert.ListStepConverter;
import net.lshift.spki.convert.ProtobufConvert;
import net.lshift.spki.suiteb.proto.ProtobufHelper;
import net.lshift.spki.suiteb.sexpstructs.EcdsaPublicKey;
import net.lshift.spki.suiteb.sexpstructs.EcdsaSignature;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;

import com.google.protobuf.Message;

/**
 * A public key for verifying signatures
 */
@ConvertClass(PublicSigningKey.Step.class)
public class PublicSigningKey
    extends PublicKey
    implements SequenceItem,
    ProtobufConvert<SuiteBProto.PublicSigningKey.Builder> {
    public static final Step stepConverter = new Step();
    private final ECDSASigner signer = new ECDSASigner();

    PublicSigningKey(final CipherParameters publicKey) {
        super(publicKey);
        signer.init(false, publicKey);
    }

    public boolean validate(final DigestSha384 digest, final EcdsaSignature sigVal) {
        return signer.verifySignature(digest.getBytes(), sigVal.r, sigVal.s);
    }

    public static class Step
            extends ListStepConverter<PublicSigningKey, EcdsaPublicKey> {

        public Step() {
            super(PublicSigningKey.class, EcdsaPublicKey.class);
        }

        @Override
        public EcdsaPublicKey stepIn(final PublicSigningKey o) {
            return new EcdsaPublicKey(o.publicKey);
        }

        @Override
        public PublicSigningKey stepOut(final EcdsaPublicKey s)
            throws ParseException {
            return new PublicSigningKey(s.getParameters());
        }
    }

    @Override
    public <ActionType extends Message> void process(final InferenceEngine<ActionType> engine, final Condition trust, Class<ActionType> actionType)
        throws InvalidInputException {
        engine.addPublicSigningKey(this);
        engine.addItemTrust(keyId, trust);
    }

    public static PublicSigningKey fromProtobuf(SuiteBProto.PublicSigningKey publicSigningKey) 
    throws ParseException, CryptographyException {
        return fromProtobuf(publicSigningKey.getPoint());
    }

    public static PublicSigningKey fromProtobuf(EcPoint point)
            throws ParseException, CryptographyException {
        return stepConverter.stepOut(
                new EcdsaPublicKey(ProtobufHelper.ecPointFromProtobuf(point)));
    }

    @Override
    public Builder toProtobufSequenceItem() {
        return SuiteBProto.SequenceItem.newBuilder()
                .setPublicSigningKey(this.toProtobuf());
    }

    @Override
    public SuiteBProto.PublicSigningKey.Builder toProtobuf() {
        return SuiteBProto.PublicSigningKey.newBuilder()
                .setPoint(stepConverter.stepIn(this).toProtobuf());
    }

}
