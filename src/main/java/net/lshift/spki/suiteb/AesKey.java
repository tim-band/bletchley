package net.lshift.spki.suiteb;

import net.lshift.spki.Constants;
import net.lshift.spki.ParseException;
import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * A key to use with AES/GCM.
 */
@Convert.ByPosition(name="aes-gcm-key", fields={"key"})
public class AesKey implements SequenceItem {

    public static final int AES_KEY_BYTES = 32;
    private static final byte[] KEYID_AD
        = "8:keyid-ad".getBytes(Constants.ASCII);
    private static final byte[] ZERO_BYTES = new byte[] { };

    public final byte[] key;
    private AesKeyId keyId;

    public AesKey(
        final byte[] key
    ) {
        this.key = key;
    }

    private AesKeyId genKeyId() {
        try {
            final GCMBlockCipher gcm = new GCMBlockCipher(new AESFastEngine());
            gcm.init(true, new AEADParameters(
                new KeyParameter(key), 128, KEYID_AD, KEYID_AD));
            final byte[] ciphertext = new byte[gcm.getOutputSize(ZERO_BYTES.length)];
            final int resp = gcm.processBytes(ZERO_BYTES, 0, ZERO_BYTES.length,
                ciphertext, 0);
            gcm.doFinal(ciphertext, resp);
            return new AesKeyId(ciphertext);
        } catch (final InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }

    public synchronized AesKeyId getKeyId() {
        if (keyId == null) {
            keyId = genKeyId();
        }
        return keyId;
    }

    public AesPacket encrypt(final SequenceItem message) {
        try {
            final byte[] nonce = Ec.randomBytes(12);
            final GCMBlockCipher gcm = new GCMBlockCipher(new AESFastEngine());
            gcm.init(true, new AEADParameters(
                new KeyParameter(key), 128, nonce, ZERO_BYTES));
            final byte[] plaintext =
                ConvertUtils.toBytes(SequenceItem.class, message);
            final byte[] ciphertext = new byte[gcm.getOutputSize(plaintext.length)];
            final int resp = gcm.processBytes(plaintext, 0, plaintext.length,
                ciphertext, 0);
            gcm.doFinal(ciphertext, resp);
            return new AesPacket(getKeyId(), nonce, ciphertext);
        } catch (final InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }

    public SequenceItem decrypt(final AesPacket packet)
        throws InvalidCipherTextException,
            ParseException {
        try {
            final GCMBlockCipher gcm = new GCMBlockCipher(new AESFastEngine());
            gcm.init(false, new AEADParameters(
                new KeyParameter(key), 128, packet.nonce, ZERO_BYTES));
            final byte[] newtext = new byte[
                gcm.getOutputSize(packet.ciphertext.length)];
            final int pp = gcm.processBytes(packet.ciphertext, 0,
                packet.ciphertext.length, newtext, 0);
            gcm.doFinal(newtext, pp);
            return ConvertUtils.fromBytes(SequenceItem.class, newtext);
        } catch (final IllegalStateException e) {
            throw new RuntimeException(e);
        }
    }

    public static AesKey generateAESKey() {
        return new AesKey(Ec.randomBytes(AES_KEY_BYTES));
    }
}
