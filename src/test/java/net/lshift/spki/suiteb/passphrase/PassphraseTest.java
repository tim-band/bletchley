package net.lshift.spki.suiteb.passphrase;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.convert.UsesSimpleMessage;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.ActionType;
import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.AesPacket;
import net.lshift.spki.suiteb.InferenceEngine;
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
    public void testRoundtrip() throws InvalidInputException {
        final KeyFromPassphrase kfp = PassphraseUtils.generate(PASSPHRASE_ID, PASSPHRASE);
        final AesKey key = kfp.getAesKey();
        final AesPacket encrypted = key.encrypt(MESSAGE);

        final PassphraseProtectedKey ppk = RoundTrip.roundTrip(PassphraseProtectedKey.class,
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

    private static void assertDecryptsToMessage(final AesKey trueKey, final AesPacket encrypted)
        throws InvalidInputException,
            ParseException {
        final SequenceItem decrypted = trueKey.decrypt(encrypted);
        assertEquals(SimpleMessage.getContent(MESSAGE),
            SimpleMessage.getContent(decrypted));
    }

    @Test
    public void testStability() throws IOException, InvalidInputException {
        final Sequence sequence = ConvertUtils.read(Sequence.class,
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
        final Sequence sequence = new Sequence(Arrays.asList(
            kfp.getPassphraseProtectedKey(),
            kfp.getAesKey().encrypt(MESSAGE)));
        final InferenceEngine engine = new InferenceEngine();
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
        engine.setBlindlyTrusting(true);
        engine.process(sequence);
        final List<ActionType> actions = engine.getActions();
        assertEquals(1, actions.size());
        assertEquals(MESSAGE.getPayload(), actions.get(0));
    }

    @Test
    public void testInferenceEngineHandlesNoDelegate() throws InvalidInputException {
        final KeyFromPassphrase kfp = PassphraseUtils.generate(PASSPHRASE_ID, PASSPHRASE);
        final Sequence sequence = new Sequence(Arrays.asList(
            kfp.getPassphraseProtectedKey(),
            kfp.getAesKey().encrypt(MESSAGE)));
        final InferenceEngine engine = new InferenceEngine();
        engine.process(sequence);
        final List<ActionType> actions = engine.getActions();
        assertEquals(0, actions.size());
    }

    @Test
    public void testInferenceEngineHandlesNoPassphrase() throws InvalidInputException {
        final KeyFromPassphrase kfp = PassphraseUtils.generate(PASSPHRASE_ID, PASSPHRASE);
        final Sequence sequence = new Sequence(Arrays.asList(
            kfp.getPassphraseProtectedKey(),
            kfp.getAesKey().encrypt(MESSAGE)));
        final InferenceEngine engine = new InferenceEngine();
        engine.setPassphraseDelegate(new PassphraseDelegate() {
            @Override
            public AesKey getPassphrase(final PassphraseProtectedKey ppk) {
                return null;
            }
        });
        engine.process(sequence);
        final List<ActionType> actions = engine.getActions();
        assertEquals(0, actions.size());
    }
}
