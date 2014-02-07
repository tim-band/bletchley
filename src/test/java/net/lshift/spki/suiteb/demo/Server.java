package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.convert.openable.OpenableUtils.write;
import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static net.lshift.spki.suiteb.Signed.signed;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicSigningKey;
import net.lshift.spki.suiteb.SequenceItem;

public class Server {
    protected final PrivateSigningKey signingKey;

    public Server() {
        signingKey = PrivateSigningKey.generate();
    }

    public PublicSigningKey getPublicSigningKey() {
        return signingKey.getPublicKey();
    }

    public void writePublicSigningKey(Openable acl) throws IOException {
        write(acl, getPublicSigningKey());
    }

    public void writeServiceMessage(Openable target, Service service)
            throws IOException, InvalidInputException {
        write(target, serviceMessage(service));
    }

    protected SequenceItem serviceMessage(Service service)
            throws IOException, InvalidInputException {
        return signedMessage(service);
    }

    protected SequenceItem signedMessage(Service service) {
        return sequence(getPublicSigningKey(),
                signed(signingKey, new Action(service)));
    }
}
