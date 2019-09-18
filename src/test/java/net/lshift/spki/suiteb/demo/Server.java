package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.suiteb.SequenceUtils.action;
import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static net.lshift.spki.suiteb.Signed.signed;
import static net.lshift.spki.suiteb.demo.Utilities.asOpenable;

import java.io.IOException;

import net.lshift.bletchley.suiteb.demo.DemoProto.Service;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.SequenceItem;

public class Server {
    protected final PrivateSigningKey signingKey = PrivateSigningKey.generate();

    public Openable writePublicSigningKey() throws IOException {
        return asOpenable(signingKey.getPublicKey());
    }

    public Openable writeServiceMessage(Service service)
            throws IOException, InvalidInputException {
        return asOpenable(serviceMessage(service));
    }

    protected SequenceItem serviceMessage(Service service)
            throws IOException, InvalidInputException {
        return signedMessage(service);
    }

    protected SequenceItem signedMessage(Service service) {
        return sequence(signingKey.getPublicKey(),
                signed(signingKey, action(service)));
    }
}
