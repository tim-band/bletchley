package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.convert.openable.OpenableUtils.write;
import static net.lshift.spki.suiteb.SequenceUtils.sequenceOrItem;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.suiteb.DigestSha384;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.SequenceItem;

public class Client
{
    final PrivateEncryptionKey decryptionKey;
    final DigestSha384 masterPublicKeyId;
    private ReadService service;
    
    public Client(DigestSha384 masterPublicKeyId) 
            throws IOException
    {
        this.decryptionKey = PrivateEncryptionKey.generate();
        this.masterPublicKeyId = masterPublicKeyId;
        
        final ByteOpenable acl = writeSequence(
            decryptionKey,
            masterPublicKeyId);
        this.service = new ReadService(acl);
    }

    public PublicEncryptionKey getPublicEncryptionKey()
    {
        return decryptionKey.getPublicKey();
    }

    private static ByteOpenable writeSequence(final SequenceItem... items) throws IOException {
        final ByteOpenable res = new ByteOpenable();
        write(res, sequenceOrItem(items));
        return res;
    }

    public Service receiveMessage(ByteOpenable message) 
            throws IOException, InvalidInputException
    {
        return service.readMessage(message);
    }
}
