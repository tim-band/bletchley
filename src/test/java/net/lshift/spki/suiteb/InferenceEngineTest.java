package net.lshift.spki.suiteb;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.UsesSimpleMessage;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.simplemessage.SimpleMessage;

import org.junit.Test;

public class InferenceEngineTest extends UsesSimpleMessage {
    @Test
    public void emptyListIfSignerHasDoneNothing() {
        PrivateSigningKey key = PrivateSigningKey.generate();
        InferenceEngine engine = new InferenceEngine();
        engine.addTrustedKey(key.getPublicKey().getKeyId());
        List<ActionType> res = engine.getActions();
        assertThat(res.size(), is(equalTo(0)));
    }

    @Test
    public void emptyListIfNotSignedByTrustedKey() throws InvalidInputException {
        PrivateSigningKey key = PrivateSigningKey.generate();
        InferenceEngine engine = new InferenceEngine();
        engine.process(key.getPublicKey());
        Action message = SimpleMessage.makeMessage(this.getClass());
        engine.process(key.sign(message));
        engine.process(message);
        List<ActionType> res = engine.getActions();
        assertThat(res.size(), is(equalTo(0)));
    }

    @Test
    public void foundIfSignedByTrustedKey() throws InvalidInputException {
        Action message = SimpleMessage.makeMessage(this.getClass());
        PrivateSigningKey key = PrivateSigningKey.generate();
        InferenceEngine engine = new InferenceEngine();
        engine.addTrustedKey(key.getPublicKey().getKeyId());
        engine.process(key.getPublicKey());
        engine.process(key.sign(message));
        engine.process(message);
        List<ActionType> res = engine.getActions();
        assertThat(res.size(), is(equalTo(1)));
        assertThat(res.get(0), is(equalTo(message.getPayload())));
    }

    @Test
    public void foundEvenInsideEncryptedBit() throws InvalidInputException {
        Action message = SimpleMessage.makeMessage(this.getClass());
        PrivateSigningKey key = PrivateSigningKey.generate();
        AesKey aeskey = AesKey.generateAESKey();
        InferenceEngine engine = new InferenceEngine();
        engine.addTrustedKey(key.getPublicKey().getKeyId());
        engine.process(key.getPublicKey());
        engine.process(aeskey);
        AesPacket encrypted = aeskey.encrypt(message);
        engine.process(key.sign(encrypted));
        engine.process(encrypted);
        List<ActionType> res = engine.getActions();
        assertThat(res.size(), is(equalTo(1)));
        assertThat(res.get(0), is(equalTo(message.getPayload())));
    }

    @Test
    public void foundIfBlindlyTrusting() throws InvalidInputException {
        Action message = SimpleMessage.makeMessage(this.getClass());
        InferenceEngine engine = new InferenceEngine();
        engine.setBlindlyTrusting(true);
        engine.process(message);
        List<ActionType> res = engine.getActions();
        assertThat(res.size(), is(equalTo(1)));
        assertThat(res.get(0), is(equalTo(message.getPayload())));
    }

    @Test
    public void foundIfEncryptionKeyProvided() throws InvalidInputException {
        List<SequenceItem> sequence = new ArrayList<SequenceItem>();
        PrivateEncryptionKey key = PrivateEncryptionKey.generate();
        sequence.add(key);
        AesKey aeskey = key.getPublicKey().setupEncrypt(sequence);
        Action message = SimpleMessage.makeMessage(this.getClass());
        sequence.add(aeskey.encrypt(message));
        InferenceEngine engine = new InferenceEngine();
        engine.setBlindlyTrusting(true);
        engine.process(new Sequence(sequence));
        List<ActionType> res = engine.getActions();
        assertThat(res.size(), is(equalTo(1)));
        assertThat(res.get(0), is(equalTo(message.getPayload())));
    }
}
