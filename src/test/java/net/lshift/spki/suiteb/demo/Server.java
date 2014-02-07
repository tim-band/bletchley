package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.convert.openable.OpenableUtils.write;
import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static net.lshift.spki.suiteb.Signed.signed;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ReadInfo;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicSigningKey;
import net.lshift.spki.suiteb.Sequence;

public class Server {
    protected static ReadInfo R = ReadInfo.BASE.extend(Service.class);

    protected final PrivateSigningKey signingKey;

    public Server() {
        signingKey = PrivateSigningKey.generate();
    }

    public PublicSigningKey getPublicSigningKey() {
        return signingKey.getPublicKey();
    }

    public ByteOpenable generateMessage(Service service) throws IOException,
            InvalidInputException {
        return asOpenable(signedMessage(service));
    }

    protected Sequence signedMessage(Service service) {
        return sequence(getPublicSigningKey(),
                signed(signingKey, new Action(service)));
    }

    protected ByteOpenable asOpenable(Sequence sequence) throws IOException {
        final ByteOpenable target = new ByteOpenable();
        write(target, sequence);
        return target;
    }
}
