package net.lshift.spki.suiteb.passphrase;

import static net.lshift.spki.suiteb.InferenceEngineTest.checkMessage;
import static net.lshift.spki.suiteb.InferenceEngineTest.checkNoMessages;
import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import net.lshift.bletchley.suiteb.proto.SimpleMessageProto;
import net.lshift.bletchley.suiteb.proto.SimpleMessageProto.SimpleMessage;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.convert.UsesSimpleMessage;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.AesPacket;
import net.lshift.spki.suiteb.InferenceEngine;
import net.lshift.spki.suiteb.Sequence;

import org.junit.Test;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

public class PassphraseTest extends UsesSimpleMessage {
    private static final String PASSPHRASE_ID = "passphrase id";
    private static final String PASSPHRASE = "passphrase";
    private static final String MESSAGE_TYPE = "passphrase test message";
    private static final String MESSAGE_TEXT = "Squeamish ossifrage";
    private static final Action MESSAGE = new Action(Any.pack(
            SimpleMessageProto.SimpleMessage.newBuilder()
            .setType(MESSAGE_TYPE)
            .setContent(ByteString.copyFrom(MESSAGE_TEXT.getBytes(StandardCharsets.US_ASCII))).build()));

    @Test
    public void testRoundtrip() throws InvalidInputException, InvalidProtocolBufferException {
        final KeyFromPassphrase kfp = PassphraseUtils.generate(PASSPHRASE_ID, PASSPHRASE);
        final AesKey key = kfp.getAesKey();
        final AesPacket encrypted = key.encrypt(MESSAGE);

        final PassphraseProtectedKey ppk = roundTrip(PassphraseProtectedKey.class,
            kfp.getPassphraseProtectedKey());
        assertEquals(PASSPHRASE_ID, ppk.getPassphraseId());
        saveTestStabilityExample(ppk, encrypted);
        assertDecryptsToMessage(ppk.getKey(PASSPHRASE), encrypted);
    }

    private void saveTestStabilityExample(final PassphraseProtectedKey ppk,
            final AesPacket encrypted) {
        try {
            ConvertUtils.write(Sequence.of(ppk, encrypted), new File("/tmp/example.pb"));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void assertDecryptsToMessage(final AesKey trueKey, final AesPacket encrypted)
        throws InvalidInputException,
            ParseException, InvalidProtocolBufferException {
        final Action decrypted = (Action) trueKey.decrypt(encrypted);
        assertMessagesMatch(
                MESSAGE.getPayload(SimpleMessage.class), 
                decrypted.getPayload(SimpleMessage.class));
    }

    @Test
    public void testStability() throws IOException, InvalidInputException {
        final Sequence sequence = ConvertUtils.read(Sequence.class, getClass().getResourceAsStream("encrypted.pb"));
        final PassphraseProtectedKey ppk = (PassphraseProtectedKey) sequence.sequence.get(0);
        final AesPacket encrypted = (AesPacket) sequence.sequence.get(1);
        assertDecryptsToMessage(ppk.getKey(PASSPHRASE), encrypted);
    }

    @Test
    public void testBadPassphraseRejected() {
        assertNull(PassphraseUtils.generate(PASSPHRASE_ID, PASSPHRASE)
                .getPassphraseProtectedKey()
                .getKey(PASSPHRASE + " "));
    }

    @Test
    public void testInferenceEngineCanRead() throws InvalidInputException {
        final KeyFromPassphrase kfp = PassphraseUtils.generate(PASSPHRASE_ID, PASSPHRASE);
        final Sequence sequence = sequence(
            kfp.getPassphraseProtectedKey(),
            kfp.getAesKey().encrypt(MESSAGE));
        final InferenceEngine<SimpleMessage> engine = newEngine();
        engine.setPassphraseDelegate(new PassphraseDelegate() {
            @Override
            public AesKey getPassphrase(final PassphraseProtectedKey ppk) {
                if (PASSPHRASE_ID.equals(ppk.getPassphraseId())) {
                        return ppk.getKey(PASSPHRASE);
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
        final InferenceEngine<SimpleMessage> engine = newEngine();
        engine.process(sequence);
        checkNoMessages(engine);
    }

    @Test
    public void testInferenceEngineHandlesNoPassphrase() throws InvalidInputException {
        final KeyFromPassphrase kfp = PassphraseUtils.generate(PASSPHRASE_ID, PASSPHRASE);
        final Sequence sequence = sequence(
            kfp.getPassphraseProtectedKey(),
            kfp.getAesKey().encrypt(MESSAGE));
        final InferenceEngine<SimpleMessage> engine = newEngine();
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
