package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.suiteb.SequenceUtils.sequence;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.suiteb.EncryptionCache;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.Sequence;

public class ServerWithEncryption extends Server {
    private PublicEncryptionKey recipient;    
    private final EncryptionCache ephemeral;

    public ServerWithEncryption() {
        ephemeral = new EncryptionCache(PrivateEncryptionKey.generate());
    }

    @Override
    public ByteOpenable generateMessage(Service service) throws IOException,
            InvalidInputException {
        return asOpenable(encrypt(signedMessage(service)));
    }

    public void setRecipient(PublicEncryptionKey recipient) {
        this.recipient = recipient;
    }
    
    protected Sequence encrypt(Sequence sequence) {
        return sequence(ephemeral.getPublicKey(),
                ephemeral.encrypt(recipient, sequence));
    }
}
