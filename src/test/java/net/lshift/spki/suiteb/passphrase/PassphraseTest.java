package net.lshift.spki.suiteb.passphrase;

import static org.junit.Assert.assertEquals;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.UsesSimpleMessage;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.AesPacket;
import net.lshift.spki.suiteb.RoundTrip;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.simplemessage.SimpleMessage;

import org.junit.Test;

public class PassphraseTest extends UsesSimpleMessage {
    private static final String PASSPHRASE_ID = "passphrase id";
    private static final String PASSPHRASE = "passphrase";

    @Test
    public void test() throws InvalidInputException {
        Action message = SimpleMessage.makeMessage(getClass());
        KeyFromPassphrase kfp = PassphraseUtils.generate(PASSPHRASE_ID, PASSPHRASE);
        AesKey key = kfp.getAesKey();
        AesPacket encrypted = key.encrypt(message);
        PassphraseProtectedKey ppk = RoundTrip.roundTrip(PassphraseProtectedKey.class,
            kfp.getPassphraseProtectedKey());
        assertEquals(PASSPHRASE_ID, ppk.getPassphraseId());
        AesKey trueKey = ppk.getKey(PASSPHRASE);
        SequenceItem decrypted = trueKey.decrypt(encrypted);
        assertEquals(SimpleMessage.getContent(message),
            SimpleMessage.getContent(decrypted));
    }

    @Test(expected=InvalidInputException.class)
    public void testBadPassphraseRejected() throws InvalidInputException {
        PassphraseUtils.generate(PASSPHRASE_ID, PASSPHRASE)
        .getPassphraseProtectedKey()
        .getKey(PASSPHRASE + " ");
    }
}
