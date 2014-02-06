package net.lshift.spki.suiteb.demo;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.PublicSigningKey;

public class Server
{
    private final PrivateSigningKey signingKey;
    private final PublicEncryptionKey recipient;
    private ByteOpenable certificate;
    
    public Server(PublicEncryptionKey recipient)
    {
        this.recipient = recipient;
        signingKey = PrivateSigningKey.generate();
    }

    public PublicSigningKey getPublicSigningKey()
    {
        return signingKey.getPublicKey();
    }

    public void setCertificate(ByteOpenable certificate)
    {
        this.certificate = certificate;        
    }

    public ByteOpenable generateMessage(Service service) 
            throws IOException, InvalidInputException
    {
        final ByteOpenable target = new ByteOpenable();
        WriteService.writeService(target, certificate, 
            signingKey, recipient, service);
        return target;
    }
}
