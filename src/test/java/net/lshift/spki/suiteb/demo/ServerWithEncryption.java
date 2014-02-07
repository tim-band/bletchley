package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.suiteb.SequenceUtils.sequence;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.suiteb.EncryptionCache;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.SequenceItem;

public class ServerWithEncryption extends Server {
    private final EncryptionCache ephemeral
        = new EncryptionCache(PrivateEncryptionKey.generate());
    private PublicEncryptionKey recipient;

    @Override
    protected SequenceItem serviceMessage(Service service) throws IOException,
            InvalidInputException {
        return encrypt(signedMessage(service));
    }

    public void setRecipient(PublicEncryptionKey recipient) {
        this.recipient = recipient;
    }

    protected SequenceItem encrypt(SequenceItem sequence) {
        return sequence(ephemeral.getPublicKey(),
                ephemeral.encrypt(recipient, sequence));
    }
}
