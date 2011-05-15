package net.lshift.spki.suiteb.cli;

import static org.junit.Assert.assertArrayEquals;

import java.io.IOException;

import net.lshift.spki.ParseException;
import net.lshift.spki.convert.ByteOpenable;
import net.lshift.spki.convert.Openable;
import net.lshift.spki.convert.OpenableUtils;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Test;

public class CLITest
{
    @Test
    public void cliTest()
        throws InvalidCipherTextException,
            ParseException,
            IOException
    {
        Openable sPrivate = new ByteOpenable();
        Openable sPublic = new ByteOpenable();
        Openable ePrivate = new ByteOpenable();
        Openable ePublic = new ByteOpenable();
        Openable message = new ByteOpenable();
        Openable packet = new ByteOpenable();
        Openable result = new ByteOpenable();

        CLI.generateSigningKey(sPrivate);
        CLI.getPublicSigningKey(sPrivate, sPublic);
        CLI.generateEncryptionKey(ePrivate);
        CLI.getPublicEncryptionKey(ePrivate, ePublic);

        final String messageType = CLITest.class.toString();
        final byte[] messageBytes
            = "the magic words are squeamish ossifrage".getBytes();
        OpenableUtils.writeBytes(message, messageBytes);
        CLI.generateEncryptedSignedMessage(messageType,
            sPrivate, ePublic, message, packet);
        CLI.decryptSignedMessage(messageType,
            ePrivate, sPublic, packet, result);
        byte[] resultBytes = OpenableUtils.readBytes(result);
        assertArrayEquals(messageBytes, resultBytes);
    }
}
