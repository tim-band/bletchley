package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.suiteb.demo.Utilities.asOpenable;
import static net.lshift.spki.suiteb.demo.Utilities.emptyByteOpenable;
import static net.lshift.spki.suiteb.demo.Utilities.newEngine;
import static net.lshift.spki.suiteb.demo.Utilities.read;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.suiteb.InferenceEngine;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;

public class Client {
    private Openable secrets = emptyByteOpenable();
    private Openable acl = emptyByteOpenable();

    private PublicEncryptionKey publicEncryptionKey = null;

    public void setAcl(Openable acl) {
        this.acl = acl;
    }

    public void generateEncryptionKeypair() throws IOException {
        PrivateEncryptionKey privateKey = PrivateEncryptionKey.generate();
        secrets = asOpenable(privateKey);
        publicEncryptionKey = privateKey.getPublicKey();
    }

    public Openable writePublicEncryptionKey() throws IOException {
        return asOpenable(publicEncryptionKey);
    }

    public Service receiveMessage(Openable message) throws IOException,
            InvalidInputException {
        final InferenceEngine engine = newEngine();
        engine.processTrusted(read(acl));
        engine.processTrusted(read(secrets));
        engine.process(read(message));
        return engine.getSoleAction(Service.class);
    }
}
