package net.lshift.spki.suiteb.demo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.PrintWriter;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.suiteb.CryptographyException;

import org.junit.Test;

/**
 * You can consider the first part of each test the setting up of the system,
 * and key management. Then, the call to sendMessageFromServerToClient is the
 * system in actual operation.
 */
public class TestLoop {
    @Test
    public void serverSendsPlainTextMessageToClientThatTrustsIt()
            throws IOException, InvalidInputException {
        Server server = new Server();
        Client client = new Client();
        client.setAcl(server.writePublicSigningKey());
        sendMessageFromServerToClient(server, client);
    }

    @Test
    public void serverSendsEncryptedMessageToClientThatTrustsIt()
            throws IOException, InvalidInputException {
        ServerWithEncryption server = new ServerWithEncryption();
        Client client = new Client();
        client.generateEncryptionKeypair();
        client.setAcl(server.writePublicSigningKey());
        server.setRecipientKey(client.writePublicEncryptionKey());

        sendMessageFromServerToClient(server, client);
    }

    @Test
    public void serverSendsEncryptedMessageToClientThatTrustsMasterServer()
            throws IOException, InvalidInputException {
        final Master master = new Master();
        final PartiallyTrustedServer server = new PartiallyTrustedServer();
        server.setCertificate(
                master.delegateTrustTo(server.getPublicSigningKey()));

        final Client client = new Client();
        client.generateEncryptionKeypair();
        client.setAcl(master.writeMasterTrust());
        server.setRecipientKey(client.writePublicEncryptionKey());

        sendMessageFromServerToClient(server, client);
    }

    @Test
    public void untrustedServerSendsMessageToClient() throws IOException,
            InvalidInputException {
        Server trustedServer = new Server();
        Server attacker = new Server();
        Client client = new Client();
        client.setAcl(trustedServer.writePublicSigningKey());
        try {
            sendMessageFromServerToClient(attacker, client);
            fail("Expected client to fail to read any trusted content from message");
        } catch (CryptographyException e) {
        }
    }

    @Test
    public void clientCannotInterceptMessage() throws IOException,
            ParseException, InvalidInputException {
        ServerWithEncryption server = new ServerWithEncryption();
        Client client = new Client();
        client.generateEncryptionKeypair();
        Client attacker = new Client();
        attacker.generateEncryptionKeypair();
        server.setRecipientKey(client.writePublicEncryptionKey());

        try {
            sendMessageFromServerToClient(server, attacker);
            fail("Expected client to fail to be able to read any content from message");
        } catch (CryptographyException e) {
        }
    }

    private void sendMessageFromServerToClient(Server server, Client client)
            throws IOException, InvalidInputException, ParseException {
        final Service service = new Service("http", 80);
        Openable message = server.writeServiceMessage(service);
        final Service readBack = client.receiveMessage(message);
        assertThat(readBack.name, is(service.name));
        assertThat(readBack.port, is(service.port));
        PrettyPrinter.prettyPrint(new PrintWriter(System.out), message.read());
    }
}
