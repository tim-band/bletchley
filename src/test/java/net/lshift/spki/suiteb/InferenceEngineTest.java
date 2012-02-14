package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.sexpstructs.Signed.signed;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.UsesSimpleMessage;
import net.lshift.spki.suiteb.sexpstructs.Cert;
import net.lshift.spki.suiteb.sexpstructs.Condition;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.simplemessage.SimpleMessage;

import org.junit.Test;

public class InferenceEngineTest extends UsesSimpleMessage {
    private void checkNoMessages(final InferenceEngine engine) {
        final List<ActionType> res = engine.getActions();
        assertThat(res.size(), is(equalTo(0)));
    }

    private void checkMessage(final InferenceEngine engine, final Action message) {
        final List<ActionType> res = engine.getActions();
        assertThat(res.size(), is(equalTo(1)));
        assertThat(res.get(0), is(equalTo(message.getPayload())));
    }

    @Test
    public void emptyListIfSignerHasDoneNothing() throws InvalidInputException {
        final PrivateSigningKey key = PrivateSigningKey.generate();
        final InferenceEngine engine = new InferenceEngine();
        engine.processTrusted(new Cert(key.getPublicKey().getKeyId(),
                Collections.<Condition>emptyList()));
        checkNoMessages(engine);
    }

    @Test
    public void emptyListIfNotSignedByTrustedKey() throws InvalidInputException {
        final PrivateSigningKey key = PrivateSigningKey.generate();
        final InferenceEngine engine = new InferenceEngine();
        engine.process(key.getPublicKey());
        final Action message = SimpleMessage.makeMessage(this.getClass());
        engine.process(key.sign(message));
        engine.process(signed(message));
        checkNoMessages(engine);
    }

    @Test
    public void foundIfSignedByTrustedKey() throws InvalidInputException {
        final Action message = SimpleMessage.makeMessage(this.getClass());
        final PrivateSigningKey key = PrivateSigningKey.generate();
        final InferenceEngine engine = new InferenceEngine();
        engine.processTrusted(new Cert(key.getPublicKey().getKeyId(),
                Collections.<Condition>emptyList()));
        engine.process(key.getPublicKey());
        engine.process(key.sign(message));
        engine.process(signed(message));
        checkMessage(engine, message);
    }

    @Test
    public void foundIfAuthorityDelegated() throws InvalidInputException {
        final Action message = SimpleMessage.makeMessage(this.getClass());
        final PrivateSigningKey masterKey = PrivateSigningKey.generate();
        final PrivateSigningKey subKey = PrivateSigningKey.generate();
        final InferenceEngine engine = new InferenceEngine();
        engine.processTrusted(new Cert(masterKey.getPublicKey().getKeyId(), Collections.<Condition>emptyList()));
        engine.process(masterKey.getPublicKey());
        Cert cert = new Cert(subKey.getPublicKey().getKeyId(),
                Collections.<Condition>emptyList());
        engine.process(masterKey.sign(cert));
        engine.process(signed(cert));
        engine.process(subKey.getPublicKey());
        engine.process(subKey.sign(message));
        engine.process(signed(message));
        checkMessage(engine, message);
    }

    @Test
    public void notFoundUnlessAuthorityDelegated() throws InvalidInputException {
        final Action message = SimpleMessage.makeMessage(this.getClass());
        final PrivateSigningKey masterKey = PrivateSigningKey.generate();
        final PrivateSigningKey subKey = PrivateSigningKey.generate();
        final InferenceEngine engine = new InferenceEngine();
        engine.processTrusted(new Cert(masterKey.getPublicKey().getKeyId(), Collections.<Condition>emptyList()));
        engine.process(masterKey.getPublicKey());
        Cert cert = new Cert(subKey.getPublicKey().getKeyId(),
                Collections.<Condition>emptyList());
        engine.process(signed(cert));
        engine.process(subKey.getPublicKey());
        engine.process(subKey.sign(message));
        engine.process(signed(message));
        checkNoMessages(engine);
    }

    @Test
    public void foundEvenInsideEncryptedBit() throws InvalidInputException {
        final Action message = SimpleMessage.makeMessage(this.getClass());
        final PrivateSigningKey key = PrivateSigningKey.generate();
        final AesKey aeskey = AesKey.generateAESKey();
        final InferenceEngine engine = new InferenceEngine();
        engine.processTrusted(new Cert(key.getPublicKey().getKeyId(), Collections.<Condition>emptyList()));
        engine.process(key.getPublicKey());
        engine.process(aeskey);
        final AesPacket encrypted = aeskey.encrypt(message);
        engine.process(key.sign(encrypted));
        engine.process(signed(encrypted));
        checkMessage(engine, message);
    }

    @Test
    public void foundIfBlindlyTrusting() throws InvalidInputException {
        final Action message = SimpleMessage.makeMessage(this.getClass());
        final InferenceEngine engine = new InferenceEngine();
        engine.processTrusted(message);
        checkMessage(engine, message);
    }

    @Test
    public void foundIfEncryptionKeyProvided() throws InvalidInputException {
        final List<SequenceItem> sequence = new ArrayList<SequenceItem>();
        final PrivateEncryptionKey key = PrivateEncryptionKey.generate();
        sequence.add(key);
        final AesKey aeskey = key.getPublicKey().setupEncrypt(sequence);
        final Action message = SimpleMessage.makeMessage(this.getClass());
        sequence.add(aeskey.encrypt(message));
        final InferenceEngine engine = new InferenceEngine();
        engine.processTrusted(new Sequence(sequence));
        checkMessage(engine, message);
    }
}
