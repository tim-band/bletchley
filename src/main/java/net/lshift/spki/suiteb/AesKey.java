package net.lshift.spki.suiteb;

import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.protobuf.ByteString;
import com.google.protobuf.Message;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ConvertUtils;

/**
 * A key to use with AES/GCM.
 */
public class AesKey implements SequenceItem {
    private static final Logger LOG = LoggerFactory.getLogger(AesKey.class);

    public static final int AES_KEY_BYTES = 32;
    private static final byte[] KEYID_AD
        = "8:keyid-ad".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] ZERO_BYTES = new byte[] { };

    public final byte[] key;
    private AesKeyId keyId;

    public AesKey(final byte[] key) {
        if(key == null) {
            throw new NullPointerException("key");
        }

        if(key.length != AES_KEY_BYTES) {
            throw new IllegalArgumentException(MessageFormat.format(
                    "Expected {0} byte key, actual {1} bytes", AES_KEY_BYTES, key.length));
        }

        this.key = key;
    }

    private AesKeyId genKeyId() {
        try {
            final GCMBlockCipher gcm = gcmBlockCipher();
            gcm.init(true, new AEADParameters(
                new KeyParameter(key), 128, KEYID_AD, KEYID_AD));
            final byte[] ciphertext = new byte[gcm.getOutputSize(ZERO_BYTES.length)];
            final int resp = gcm.processBytes(ZERO_BYTES, 0, ZERO_BYTES.length,
                ciphertext, 0);
            gcm.doFinal(ciphertext, resp);
            return new AesKeyId(ciphertext);
        } catch (final InvalidCipherTextException e) {
            // Should be impossible when we're encrypting!
            throw new AssertionError(
                "Unexpected behaviour in crypto libraries", e);
        }
    }

    public synchronized AesKeyId getKeyId() {
        if (keyId == null) {
            keyId = genKeyId();
        }
        return keyId;
    }

    public AesPacket encrypt(final SequenceItem message) {
            final byte[] nonce = Ec.randomBytes(12);
            final GCMBlockCipher gcm = gcmBlockCipher();
            gcm.init(true, new AEADParameters(
                new KeyParameter(key), 128, nonce, ZERO_BYTES));
            final byte[] plaintext = ConvertUtils.toBytes(message);
            final byte[] ciphertext = new byte[gcm.getOutputSize(plaintext.length)];
            final int resp = gcm.processBytes(plaintext, 0, plaintext.length,
                ciphertext, 0);
            try {
                gcm.doFinal(ciphertext, resp);
            } catch (final InvalidCipherTextException e) {
                // Should be impossible when we're encrypting!
                throw new AssertionError(
                    "Unexpected behaviour in crypto libraries", e);
            }
            return new AesPacket(getKeyId(), nonce, ciphertext);
    }

    public SequenceItem decrypt(final AesPacket packet)
        throws InvalidInputException {
        final GCMBlockCipher gcm = gcmBlockCipher();
        gcm.init(false, new AEADParameters(
            new KeyParameter(key), 128, packet.nonce, ZERO_BYTES));
        final byte[] newtext = new byte[
            gcm.getOutputSize(packet.ciphertext.length)];
        final int pp = gcm.processBytes(packet.ciphertext, 0,
            packet.ciphertext.length, newtext, 0);
        try {
            gcm.doFinal(newtext, pp);
        } catch (final InvalidCipherTextException e) {
            throw new CryptographyException(e);
        }

        return SequenceItem.fromProtobuf(newtext);
    }

    private GCMBlockCipher gcmBlockCipher() {
        return new GCMBlockCipher(new AESEngine());
    }

    public static AesKey generateAESKey() {
        return new AesKey(Ec.randomBytes(AES_KEY_BYTES));
    }

    @Override
    public <ActionType extends Message> void process(final InferenceEngine<ActionType> engine, final Condition trust, Class<ActionType> actionType)
        throws InvalidInputException {
        LOG.debug("Added key {}", keyId);
        engine.addAesKey(this);
    }

    @Override
    public SuiteBProto.SequenceItem.Builder toProtobuf() {
        return SuiteBProto.SequenceItem.newBuilder().setAesKey(
                SuiteBProto.AesKey.newBuilder().setKey(ByteString.copyFrom(key)));       
    }
}
