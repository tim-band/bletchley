package net.lshift.spki.suiteb;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

/**
 * Exercise GCM using the bouncycastle API.
 */
public class GcmTest {
    private final static int MAC_BYTES = 16;
    @Test
    public void gcmTest() throws IllegalStateException, InvalidCipherTextException {
        final byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) i;
        }
        AESFastEngine aes = new AESFastEngine();
        GCMBlockCipher gcm = new GCMBlockCipher(aes);
        AEADParameters aeadparams = new AEADParameters(new KeyParameter(key), MAC_BYTES*8, key, new byte[0]);
        gcm.init(true, aeadparams);
        byte[] plaintext = key;
        byte[] ciphertext = new byte[gcm.getOutputSize(plaintext.length)];
        assert ciphertext.length == plaintext.length + MAC_BYTES;
        int resp = 0;
        resp += gcm.processBytes(key, 0, plaintext.length, ciphertext, resp);
        resp += gcm.doFinal(ciphertext, resp);
        assert resp == ciphertext.length;
        byte[] mac = gcm.getMac();
        byte[] cmac = new byte[MAC_BYTES];
        System.arraycopy(ciphertext, plaintext.length, cmac, 0, MAC_BYTES);
        assertArrayEquals(mac, cmac);
        GCMBlockCipher dgcm = new GCMBlockCipher(aes);
        dgcm.init(false, aeadparams);
        byte[] newtext = new byte[dgcm.getOutputSize(ciphertext.length)];
        int pp = 0;
        pp += dgcm.processBytes(ciphertext, pp, ciphertext.length, newtext, pp);
        assert pp == 32;
        pp += dgcm.doFinal(newtext, pp);
        byte[] outmac = gcm.getMac();
        assertArrayEquals(outmac, cmac);
        assertArrayEquals(key, newtext);
    }
}