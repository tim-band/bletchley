package net.lshift.spki.suiteb.demo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.io.PrintWriter;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.convert.openable.ByteOpenable;
import org.junit.Test;

public class TestLoop {
    @Test
    public void serverSendsPlainTextMessageToClientThatTrustsIt()
            throws IOException, InvalidInputException {
        Server server = new Server();
        Client client = new Client(server.getPublicSigningKey().getKeyId());

        final Service service = new Service("http", 80);
        final ByteOpenable message = server.generateMessage(service);
        receiveMessage(client, service, message);
    }

    @Test
    public void serverSendsEncryptedMessageToClientThatTrustsIt()
            throws IOException, InvalidInputException {
        Server server = new Server();
        Client client = new Client(server.getPublicSigningKey().getKeyId());

        final Service service = new Service("http", 80);
        final ByteOpenable message = server.generateEncryptedMessageFor(
                service, client.getPublicEncryptionKey());
        receiveMessage(client, service, message);
    }

    @Test
    public void serverSendsEncryptedMessageToClientThatTrustsMasterServer()
            throws IOException, InvalidInputException {
        final Master master = new Master();
        final Server server = new Server();
        final Client client = new Client(master.getMasterPublicKeyId());
        server.setCertificate(master.delegateTrustTo(server
                .getPublicSigningKey()));

        final Service service = new Service("http", 80);
        final ByteOpenable message = server.generateEncryptedMessageFor(
                service, client.getPublicEncryptionKey());
        receiveMessage(client, service, message);
    }

    private void receiveMessage(Client client, final Service service,
            final ByteOpenable message) throws IOException,
            InvalidInputException, ParseException {
        final Service readBack = client.receiveMessage(message);
        assertThat(readBack.name, is(service.name));
        assertThat(readBack.port, is(service.port));
        PrettyPrinter.prettyPrint(new PrintWriter(System.out), message.read());
    }
}
