package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.convert.openable.OpenableUtils.read;
import static net.lshift.spki.convert.openable.OpenableUtils.write;
import static net.lshift.spki.suiteb.InferenceVariables.setNow;
import static net.lshift.spki.suiteb.demo.Utilities.R;
import static net.lshift.spki.suiteb.demo.Utilities.emptyByteOpenable;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.suiteb.InferenceEngine;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;

public class Client {
    private final Openable secrets = emptyByteOpenable();
    private final Openable acl = emptyByteOpenable();

    private PublicEncryptionKey publicEncryptionKey = null;

    private InferenceEngine newEngine() {
        final InferenceEngine engine = new InferenceEngine(R);
        setNow(engine);
        return engine;
    }

    public Openable getAcl() {
        return acl;
    }

    public void generateEncryptionKeypair() throws IOException {
        PrivateEncryptionKey privateKey = PrivateEncryptionKey.generate();
        write(secrets, privateKey);
        publicEncryptionKey = privateKey.getPublicKey();
    }

    public Service receiveMessage(Openable message) throws IOException,
            InvalidInputException {
        final InferenceEngine engine = newEngine();
        engine.processTrusted(read(R, acl));
        engine.processTrusted(read(R, secrets));
        engine.process(read(R, message));
        return engine.getSoleAction(Service.class);
    }

    public PublicEncryptionKey getPublicEncryptionKey() {
        return publicEncryptionKey;
    }
}
