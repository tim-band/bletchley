package net.lshift.spki.suiteb.passphrase;

import static org.junit.Assert.assertEquals;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.convert.UsesSimpleMessage;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.AesPacket;
import net.lshift.spki.suiteb.RoundTrip;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.simplemessage.SimpleMessage;

import org.junit.Test;

public class PassphraseTest extends UsesSimpleMessage {
    private static final String PASSPHRASE_ID = "passphrase id";
    private static final String PASSPHRASE = "passphrase";
    private static final String MESSAGE_TYPE = "passphrase test message";
    private static final String MESSAGE_TEXT = "Squeamish ossifrage";
    private static final Action MESSAGE
        = SimpleMessage.makeMessage(MESSAGE_TYPE, MESSAGE_TEXT);

    @Test
    public void test() throws InvalidInputException {
        KeyFromPassphrase kfp = PassphraseUtils.generate(PASSPHRASE_ID, PASSPHRASE);
        AesKey key = kfp.getAesKey();
        AesPacket encrypted = key.encrypt(MESSAGE);

        PassphraseProtectedKey ppk = RoundTrip.roundTrip(PassphraseProtectedKey.class,
            kfp.getPassphraseProtectedKey());
        assertEquals(PASSPHRASE_ID, ppk.getPassphraseId());
//        try {
//            ConvertUtils.write(Sequence.class, new Sequence(
//                Arrays.asList(
//                    ppk,
//                    encrypted
//                    )), new File("/tmp/saveme"));
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            throw new RuntimeException(e);
//        }
        assertDecryptsToMessage(ppk.getKey(PASSPHRASE), encrypted);
    }

    private void assertDecryptsToMessage(AesKey trueKey, AesPacket encrypted)
        throws InvalidInputException,
            ParseException {
        SequenceItem decrypted = trueKey.decrypt(encrypted);
        assertEquals(SimpleMessage.getContent(MESSAGE),
            SimpleMessage.getContent(decrypted));
    }

    @Test
    public void testStability() throws IOException, InvalidInputException {
        Sequence sequence = ConvertUtils.read(Sequence.class,
            getClass().getResourceAsStream("encrypted.spki"));
        PassphraseProtectedKey ppk = (PassphraseProtectedKey) sequence.sequence.get(0);
        AesPacket encrypted = (AesPacket) sequence.sequence.get(1);
        assertDecryptsToMessage(ppk.getKey(PASSPHRASE), encrypted);
    }

    @Test(expected=InvalidInputException.class)
    public void testBadPassphraseRejected() throws InvalidInputException {
        PassphraseUtils.generate(PASSPHRASE_ID, PASSPHRASE)
        .getPassphraseProtectedKey()
        .getKey(PASSPHRASE + " ");
    }
}
