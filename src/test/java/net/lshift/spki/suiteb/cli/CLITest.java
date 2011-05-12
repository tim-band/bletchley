package net.lshift.spki.suiteb.cli;

import static org.junit.Assert.assertArrayEquals;

import org.junit.Test;

public class CLITest
{
    @Test
    public void cliTest()
    {
        byte [] sPrivate = CLI.generateSigningKey();
        byte [] sPublic = CLI.getPublicSigningKey(sPrivate);
        byte [] ePrivate = CLI.generateEncryptionKey();
        byte [] ePublic = CLI.getPublicEncryptionKey(ePrivate);

        final String messageType = CLITest.class.toString();
        final byte[] message = "the magic words are squeamish ossifrage".getBytes();
        byte [] packet = CLI.generateEncryptedSignedMessage(
            sPrivate, ePublic, messageType, message);
        byte [] result = CLI.decryptSignedMessage(
            ePrivate, sPublic, messageType, packet);
        assertArrayEquals(message, result);
    }
}
