package net.lshift.spki.suiteb;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.suiteb.sexpstructs.EcdhPrivateKey;

/**
 * A private key for decrypting data.
 */
public class PrivateEncryptionKey implements SequenceItem {
    private final PublicEncryptionKey publicKey;
    private final AsymmetricCipherKeyPair keyPair;

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

    @Override
    public void process(
            final InferenceEngine engine, 
            final Condition trust)
        throws InvalidInputException {
        engine.addPrivateEncryptionKey(this);
    }

    public static SequenceItem fromProtobuf(
            net.lshift.bletchley.suiteb.proto.SuiteBProto.PrivateEncryptionKey privateEncryptionKey)
            throws ParseException, CryptographyException {
        final EcdhPrivateKey s = EcdhPrivateKey.fromProtobuf(privateEncryptionKey);
        return new PrivateEncryptionKey(
                s.publicKey,
                s.publicKey.getKeyPair(s.d));
    }

    @Override
    public SuiteBProto.SequenceItem.Builder toProtobuf() {
        return SuiteBProto.SequenceItem.newBuilder().setPrivateEncryptionKey(
                SuiteBProto.PrivateEncryptionKey.newBuilder()
                    .setKey(new EcdhPrivateKey(this.publicKey,
                            ((ECPrivateKeyParameters)this.keyPair.getPrivate()).getD()).toProtobuf()));
    }
}
