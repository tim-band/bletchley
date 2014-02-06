package net.lshift.spki.suiteb.demo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.io.PrintWriter;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.convert.openable.ByteOpenable;
import org.junit.Test;

public class TestLoop {
    @Test
    public void test() throws IOException, InvalidInputException {
        final Master master = new Master();
        // A client that trusts things signed by the master's key
        final Client client = new Client(master.getMasterPublicKeyId());
        // A server that wants to send encrypted messages to client
        // and have the client trust those messages
        final Server server = new Server(client.getPublicEncryptionKey());
        
        // This happens somehow - perhaps out of band, possibly by 
        // exchanging messages over the network. Either way, the server
        // gives its public key to the master server, and the
        // master server decides it trusts this server to some extent
        // and signs its public key
        server.setCertificate(master.delegateTrustTo(server.getPublicSigningKey()));

        final Service service = new Service("http", 80);
        final ByteOpenable message = server.generateMessage(service);
        final Service readBack = client.receiveMessage(message);
        assertThat(readBack.name, is(service.name));
        assertThat(readBack.port, is(service.port));
        PrettyPrinter.prettyPrint(
            new PrintWriter(System.out), message.read());
    }
}
