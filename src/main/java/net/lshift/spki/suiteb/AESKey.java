package net.lshift.spki.suiteb;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import net.lshift.spki.Constants;
import net.lshift.spki.Marshal;
import net.lshift.spki.ParseException;
import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertable;
import net.lshift.spki.convert.SExpName;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

public class AESKey extends PositionBeanConvertable implements SequenceItem
{
    public static final int AES_KEY_BYTES = 32;
    private static final byte[] KEYID_NONCE = new byte[] { 0 };
    private static final byte[] KEYID_AD
        = "8:keyid-ad".getBytes(Constants.UTF8);
    private static final byte[] KEYID_PLAINTEXT = new byte[] { };

    public final byte[] key;

    @SExpName("aes-gcm-key")
    public AESKey(
        @P("key") byte[] key
    ) {
        super();
        this.key = key;
    }

    public AESKeyId getKeyId() {
        AEADParameters aeadparams = new AEADParameters(
            new KeyParameter(key), 128, KEYID_NONCE, KEYID_AD);
        GCMBlockCipher gcm = new GCMBlockCipher(new AESFastEngine());
        gcm.init(true, aeadparams);
        byte[] ciphertext = new byte[gcm.getOutputSize(KEYID_PLAINTEXT.length)];
        int resp = 0;
        resp += gcm.processBytes(KEYID_PLAINTEXT, 0, KEYID_PLAINTEXT.length,
            ciphertext, resp);
        try {
            resp += gcm.doFinal(ciphertext, resp);
        } catch (IllegalStateException e) {
            throw new RuntimeException(e);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
        return new AESKeyId(ciphertext);

    }

    public AESPacket encrypt(SequenceItem message)
    {
        byte[] nonce = EC.randomBytes(16);
        AEADParameters aeadparams = new AEADParameters(
            new KeyParameter(key), 128, nonce, new byte[0]);
        GCMBlockCipher gcm = new GCMBlockCipher(new AESFastEngine());
        gcm.init(true, aeadparams);
        byte[] plaintext = Marshal.marshal(Convert.toSExp(SequenceItem.class, message));
        byte[] ciphertext = new byte[gcm.getOutputSize(plaintext.length)];
        int resp = 0;
        resp += gcm.processBytes(plaintext, 0, plaintext.length,
            ciphertext, resp);
        try {
            resp += gcm.doFinal(ciphertext, resp);
        } catch (IllegalStateException e) {
            throw new RuntimeException(e);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
        return new AESPacket(getKeyId(), nonce, ciphertext);
    }

    public SequenceItem decrypt(AESPacket packet) throws InvalidCipherTextException, ParseException
    {
        AEADParameters aeadparams = new AEADParameters(
            new KeyParameter(key), 128, packet.nonce, new byte[0]);
        GCMBlockCipher gcm = new GCMBlockCipher(new AESFastEngine());
        gcm.init(false, aeadparams);
        byte[] newtext = new byte[gcm.getOutputSize(packet.ciphertext.length)];
        int pp = 0;
        pp += gcm.processBytes(packet.ciphertext, pp,
            packet.ciphertext.length, newtext, pp);
        try {
            pp += gcm.doFinal(newtext, pp);
        } catch (IllegalStateException e) {
            throw new RuntimeException(e);
        }
        return Convert.fromSExp(SequenceItem.class, Marshal.unmarshal(newtext));
    }

    public static AESKey generateAESKey()
    {
        return new AESKey(EC.randomBytes(AES_KEY_BYTES));
    }
}
