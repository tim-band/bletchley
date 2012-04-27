package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.InferenceVariables.NOW;
import static net.lshift.spki.suiteb.Limit.limit;
import static net.lshift.spki.suiteb.Signed.signed;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.UsesSimpleMessage;

import org.junit.Test;

public class InferenceEngineTest extends UsesSimpleMessage {
    public static void checkNoMessages(final InferenceEngine engine) {
        final List<ActionType> res = engine.getActions();
        assertThat(res.size(), is(equalTo(0)));
    }

    public static void checkMessage(final InferenceEngine engine, final Action message) throws CryptographyException {
        assertMessagesMatch(engine.getSoleAction(), message.getPayload());
    }

    @Test
    public void emptyListIfSignerHasDoneNothing() throws InvalidInputException {
        final PrivateSigningKey key = PrivateSigningKey.generate();
        final InferenceEngine engine = newEngine();
        engine.processTrusted(key.getPublicKey());
        checkNoMessages(engine);
    }

    @Test
    public void emptyListIfNotSignedByTrustedKey() throws InvalidInputException {
        final PrivateSigningKey key = PrivateSigningKey.generate();
        final InferenceEngine engine = newEngine();
        engine.process(key.getPublicKey());
        final Action message = makeMessage();
        engine.process(signed(key, message));
        checkNoMessages(engine);
    }

    @Test
    public void foundIfSignedByTrustedKey() throws InvalidInputException {
        final Action message = makeMessage();
        final PrivateSigningKey key = PrivateSigningKey.generate();
        final InferenceEngine engine = newEngine();
        engine.processTrusted(key.getPublicKey());
        engine.process(signed(key, message));
        checkMessage(engine, message);
    }

    @Test
    public void untrustedDestroysTrust() throws InvalidInputException {
        final Action message = makeMessage();
        final PrivateSigningKey key = PrivateSigningKey.generate();
        final InferenceEngine engine = newEngine();
        engine.processTrusted(limit(key.getPublicKey(),
            UntrustedCondition.UNTRUSTED));
        engine.process(signed(key, message));
        checkNoMessages(engine);
    }

    @Test
    public void foundIfAuthorityDelegated() throws InvalidInputException {
        final Action message = makeMessage();
        final PrivateSigningKey masterKey = PrivateSigningKey.generate();
        final PrivateSigningKey subKey = PrivateSigningKey.generate();
        final InferenceEngine engine = newEngine();
        engine.processTrusted(masterKey.getPublicKey());
        engine.process(signed(masterKey, subKey.getPublicKey()));
        engine.process(signed(subKey, message));
        checkMessage(engine, message);
    }

    @Test
    public void notFoundUnlessAuthorityDelegated() throws InvalidInputException {
        final Action message = makeMessage();
        final PrivateSigningKey masterKey = PrivateSigningKey.generate();
        final PrivateSigningKey subKey = PrivateSigningKey.generate();
        final InferenceEngine engine = newEngine();
        engine.processTrusted(masterKey.getPublicKey());
        engine.process(signed(subKey.getPublicKey()));
        engine.process(signed(subKey, message));
        checkNoMessages(engine);
    }

    @Test
    public void foundEvenInsideEncryptedBit() throws InvalidInputException {
        final Action message = makeMessage();
        final PrivateSigningKey key = PrivateSigningKey.generate();
        final AesKey aeskey = AesKey.generateAESKey();
        final InferenceEngine engine = newEngine();
        engine.processTrusted(key.getPublicKey());
        engine.process(aeskey);
        final AesPacket encrypted = aeskey.encrypt(message);
        engine.process(signed(key, encrypted));
        checkMessage(engine, message);
    }

    @Test
    public void foundIfBlindlyTrusting() throws InvalidInputException {
        final Action message = makeMessage();
        final InferenceEngine engine = newEngine();
        engine.processTrusted(message);
        checkMessage(engine, message);
    }

    @Test
    public void foundIfEncryptionKeyProvided() throws InvalidInputException {
        final List<SequenceItem> sequence = new ArrayList<SequenceItem>();
        final PrivateEncryptionKey key = PrivateEncryptionKey.generate();
        sequence.add(key);
        final EncryptionCache ephemeral = EncryptionCache.ephemeralKey();
        sequence.add(ephemeral.getPublicKey());
        final Action message = makeMessage();
        final PublicEncryptionKey recipient = key.getPublicKey();
        sequence.add(ephemeral.encrypt(recipient, message));
        final InferenceEngine engine = newEngine();
        engine.processTrusted(new Sequence(sequence));
        checkMessage(engine, message);
    }

    @Test(expected = IllegalStateException.class)
    public void timeCanOnlyBeSetOnce() {
        final InferenceEngine engine = newEngine();
        NOW.set(engine, new Date());
        NOW.set(engine, new Date());
    }

    @Test(expected = IllegalStateException.class)
    public void failsIfNoDateSet() throws InvalidInputException {
        final Action message = makeMessage();
        final PrivateSigningKey key = PrivateSigningKey.generate();
        final InferenceEngine engine = newEngine();
        engine.processTrusted(limit(key.getPublicKey(),
            new InvalidOnOrAfter(new Date())));
        engine.process(signed(key, message));
    }

    @Test
    public void succeedsIfEarly() throws InvalidInputException {
        final Action message = makeMessage();
        final Date now = new Date();
        final Date later = new Date(now.getTime() + 1000000);
        final PrivateSigningKey key = PrivateSigningKey.generate();
        final InferenceEngine engine = newEngine();
        NOW.set(engine, now);
        engine.processTrusted(limit(key.getPublicKey(),
            new InvalidOnOrAfter(later)));
        engine.process(signed(key, message));
        checkMessage(engine, message);
    }

    @Test
    public void failsIfLate() throws InvalidInputException {
        final Action message = makeMessage();
        final Date now = new Date();
        final Date earlier = new Date(now.getTime() - 1000000);
        final PrivateSigningKey key = PrivateSigningKey.generate();
        final InferenceEngine engine = newEngine();
        NOW.set(engine, now);
        engine.processTrusted(limit(key.getPublicKey(),
            new InvalidOnOrAfter(earlier)));
        engine.process(key.getPublicKey());
        engine.process(signed(key, message));
        checkNoMessages(engine);
    }
}
