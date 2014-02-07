package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.convert.openable.OpenableUtils.read;
import static net.lshift.spki.convert.openable.OpenableUtils.write;
import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static net.lshift.spki.suiteb.Signed.signed;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ReadInfo;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.EncryptionCache;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.PublicSigningKey;
import net.lshift.spki.suiteb.Sequence;

public class Server {
    private static ReadInfo R = ReadInfo.BASE.extend(Service.class);
    private EncryptionCache ephemeral;

    private final PrivateSigningKey signingKey;
    private ByteOpenable certificate;

    public Server() {
        signingKey = PrivateSigningKey.generate();
        ephemeral = new EncryptionCache(PrivateEncryptionKey.generate());
    }

    public PublicSigningKey getPublicSigningKey() {
        return signingKey.getPublicKey();
    }

    public void setCertificate(ByteOpenable certificate) {
        this.certificate = certificate;
    }

    public ByteOpenable generateMessage(Service service) throws IOException,
            InvalidInputException {
        return asOpenable(signedMessage(service));
    }

    public ByteOpenable generateEncryptedMessageFor(Service service,
            PublicEncryptionKey recipient) throws IOException,
            InvalidInputException {
        return asOpenable(sequence(ephemeral.getPublicKey(),
                ephemeral.encrypt(recipient, signedMessage(service))));
    }

    private Sequence signedMessage(Service service) throws IOException,
            InvalidInputException {
        Sequence message = sequence(getPublicSigningKey(),
                signed(signingKey, new Action(service)));
        if (certificate != null) {
            message = sequence(read(R, certificate), message);
        }
        return message;
    }

    private ByteOpenable asOpenable(Sequence sequence) throws IOException {
        final ByteOpenable target = new ByteOpenable();
        write(target, sequence);
        return target;
    }
}
