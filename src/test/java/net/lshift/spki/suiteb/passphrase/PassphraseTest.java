package net.lshift.spki.suiteb.passphrase;

import static net.lshift.spki.suiteb.InferenceEngineTest.checkMessage;
import static net.lshift.spki.suiteb.InferenceEngineTest.checkNoMessages;
import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static org.junit.Assert.assertEquals;

import java.io.IOException;

import net.lshift.spki.Constants;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.convert.UsesSimpleMessage;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.AesPacket;
import net.lshift.spki.suiteb.InferenceEngine;
import net.lshift.spki.suiteb.Sequence;
import net.lshift.spki.suiteb.simplemessage.SimpleMessage;

import org.junit.Test;

public class PassphraseTest extends UsesSimpleMessage {
    private static final String PASSPHRASE_ID = "passphrase id";
    private static final String PASSPHRASE = "passphrase";
    private static final String MESSAGE_TYPE = "passphrase test message";
    private static final String MESSAGE_TEXT = "Squeamish ossifrage";
    private static final Action MESSAGE = new Action(new SimpleMessage(
        MESSAGE_TYPE, MESSAGE_TEXT.getBytes(Constants.ASCII)));

    @Test
    public void testRoundtrip() throws InvalidInputException {
        final KeyFromPassphrase kfp = PassphraseUtils.generate(PASSPHRASE_ID, PASSPHRASE);
        final AesKey key = kfp.getAesKey();
        final AesPacket encrypted = key.encrypt(MESSAGE);

        final PassphraseProtectedKey ppk = roundTrip(PassphraseProtectedKey.class,
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

    private void assertDecryptsToMessage(final AesKey trueKey, final AesPacket encrypted)
        throws InvalidInputException,
            ParseException {
        final Action decrypted = (Action) trueKey.decrypt(C, encrypted);
        assertMessagesMatch(MESSAGE.getPayload(), decrypted.getPayload());
    }

    @Test
    public void testStability() throws IOException, InvalidInputException {
        final Sequence sequence = ConvertUtils.read(C, Sequence.class,
            getClass().getResourceAsStream("encrypted.spki"));
        final PassphraseProtectedKey ppk = (PassphraseProtectedKey) sequence.sequence.get(0);
        final AesPacket encrypted = (AesPacket) sequence.sequence.get(1);
        assertDecryptsToMessage(ppk.getKey(PASSPHRASE), encrypted);
    }

    @Test(expected=InvalidInputException.class)
    public void testBadPassphraseRejected() throws InvalidInputException {
        PassphraseUtils.generate(PASSPHRASE_ID, PASSPHRASE)
        .getPassphraseProtectedKey()
        .getKey(PASSPHRASE + " ");
    }

    @Test
    public void testInferenceEngineCanRead() throws InvalidInputException {
        final KeyFromPassphrase kfp = PassphraseUtils.generate(PASSPHRASE_ID, PASSPHRASE);
        final Sequence sequence = sequence(
            kfp.getPassphraseProtectedKey(),
            kfp.getAesKey().encrypt(MESSAGE));
        final InferenceEngine engine = newEngine();
        engine.setPassphraseDelegate(new PassphraseDelegate() {
            @Override
            public AesKey getPassphrase(final PassphraseProtectedKey ppk) {
                if (PASSPHRASE_ID.equals(ppk.getPassphraseId())) {
                    try {
                        return ppk.getKey(PASSPHRASE);
                    } catch (final InvalidInputException e) {
                        return null;
                    }
                }
                return null;
            }
        });
        engine.processTrusted(sequence);
        checkMessage(engine, MESSAGE);
    }

    @Test
    public void testInferenceEngineHandlesNoDelegate() throws InvalidInputException {
        final KeyFromPassphrase kfp = PassphraseUtils.generate(PASSPHRASE_ID, PASSPHRASE);
        final Sequence sequence = sequence(
            kfp.getPassphraseProtectedKey(),
            kfp.getAesKey().encrypt(MESSAGE));
        final InferenceEngine engine = newEngine();
        engine.process(sequence);
        checkNoMessages(engine);
    }

    @Test
    public void testInferenceEngineHandlesNoPassphrase() throws InvalidInputException {
        final KeyFromPassphrase kfp = PassphraseUtils.generate(PASSPHRASE_ID, PASSPHRASE);
        final Sequence sequence = sequence(
            kfp.getPassphraseProtectedKey(),
            kfp.getAesKey().encrypt(MESSAGE));
        final InferenceEngine engine = newEngine();
        engine.setPassphraseDelegate(new PassphraseDelegate() {
            @Override
            public AesKey getPassphrase(final PassphraseProtectedKey ppk) {
                return null;
            }
        });
        engine.process(sequence);
        checkNoMessages(engine);
    }
}
