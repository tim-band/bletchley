package net.lshift.spki.suiteb;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.convert.Convert.ConvertClass;
import net.lshift.spki.convert.ListStepConverter;
import net.lshift.spki.convert.ProtobufConvert;
import net.lshift.spki.suiteb.sexpstructs.EcdhPrivateKey;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;

import com.google.protobuf.Message;

/**
 * A private key for decrypting data.
 */
@ConvertClass(PrivateEncryptionKey.Step.class)
public class PrivateEncryptionKey implements SequenceItem, 
 ProtobufConvert<SuiteBProto.PrivateEncryptionKey.Builder> {
    private final PublicEncryptionKey publicKey;
    private final AsymmetricCipherKeyPair keyPair;
    private static final Step stepConverter = new Step();


    private PrivateEncryptionKey(final PublicEncryptionKey publicKey,
                                 final AsymmetricCipherKeyPair keyPair) {
        this.publicKey = publicKey;
        this.keyPair = keyPair;
    }

    // FIXME: cache this or regenerate every time?
    public PublicEncryptionKey getPublicKey() {
        return publicKey;
    }

    public static PrivateEncryptionKey generate() {
        final AsymmetricCipherKeyPair keyPair = Ec.generate();
        return new PrivateEncryptionKey(
            new PublicEncryptionKey(keyPair.getPublic()),
            keyPair);
    }

    public AesKey getKeyAsSender(final PublicEncryptionKey receiverKey) {
        return Ec.sessionKey(
            receiverKey.publicKey,
            keyPair.getPublic(),
            keyPair.getPrivate(),
            receiverKey.publicKey);
    }

    public AesKey getKeyAsReceiver(final PublicEncryptionKey senderKey) {
        return Ec.sessionKey(
            keyPair.getPublic(),
            senderKey.publicKey,
            keyPair.getPrivate(),
            senderKey.publicKey);
    }

    public static class Step
            extends ListStepConverter<PrivateEncryptionKey, EcdhPrivateKey> {

        public Step() {
            super(PrivateEncryptionKey.class, EcdhPrivateKey.class);
        }

        @SuppressWarnings("synthetic-access")
        @Override
        public EcdhPrivateKey stepIn(final PrivateEncryptionKey o) {
            return new EcdhPrivateKey(o.publicKey,
                ((ECPrivateKeyParameters)o.keyPair.getPrivate()).getD());
        }

        @SuppressWarnings("synthetic-access")
        @Override
        public PrivateEncryptionKey stepOut(final EcdhPrivateKey s)
            throws ParseException, CryptographyException {
            return new PrivateEncryptionKey(
                s.publicKey,
                s.publicKey.getKeyPair(s.d));
        }
    }

    @Override
    public <ActionType extends Message> void process(final InferenceEngine<ActionType> engine, final Condition trust, Class<ActionType> actionType)
        throws InvalidInputException {
        engine.addPrivateEncryptionKey(this);
    }

    public static SequenceItem fromProtobuf(
            net.lshift.bletchley.suiteb.proto.SuiteBProto.PrivateEncryptionKey privateEncryptionKey)
            throws ParseException, CryptographyException {
        return stepConverter.stepOut(
                EcdhPrivateKey.fromProtobuf(privateEncryptionKey));
    }

    @Override
    public SuiteBProto.SequenceItem.Builder toProtobufSequenceItem() {
        return SuiteBProto.SequenceItem.newBuilder().setPrivateEncryptionKey(toProtobuf());
    }

    @Override
    public SuiteBProto.PrivateEncryptionKey.Builder toProtobuf() {
        return SuiteBProto.PrivateEncryptionKey.newBuilder()
                .setKey(stepConverter.stepIn(this).toProtobuf());
    }
}
