package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.convert.openable.OpenableUtils.read;
import static net.lshift.spki.convert.openable.OpenableUtils.write;
import static net.lshift.spki.suiteb.InferenceVariables.setNow;
import static net.lshift.spki.suiteb.SequenceUtils.sequence;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ReadInfo;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.suiteb.DigestSha384;
import net.lshift.spki.suiteb.InferenceEngine;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.Sequence;

public class Client {
    private static final ReadInfo R = ReadInfo.BASE.extend(Service.class);

    final PrivateEncryptionKey decryptionKey;
    final DigestSha384 masterPublicKeyId;

    public Client(DigestSha384 masterPublicKeyId) throws IOException {
        this.decryptionKey = PrivateEncryptionKey.generate();
        this.masterPublicKeyId = masterPublicKeyId;
    }

    public PublicEncryptionKey getPublicEncryptionKey() {
        return decryptionKey.getPublicKey();
    }

    public Service receiveMessage(ByteOpenable message) throws IOException,
            InvalidInputException {
        final InferenceEngine engine = newEngine();
        final ByteOpenable acl = makeAcl();
        engine.processTrusted(read(R, acl));
        engine.process(read(R, message));
        return engine.getSoleAction(Service.class);
    }

    private InferenceEngine newEngine() {
        final InferenceEngine engine = new InferenceEngine(R);
        setNow(engine);
        return engine;
    }

    private ByteOpenable makeAcl() throws IOException {
        return asOpenable(sequence(decryptionKey, masterPublicKeyId));
    }

    private ByteOpenable asOpenable(Sequence sequence) throws IOException {
        final ByteOpenable target = new ByteOpenable();
        write(target, sequence);
        return target;
    }
}
