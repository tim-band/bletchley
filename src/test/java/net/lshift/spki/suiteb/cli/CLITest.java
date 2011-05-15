package net.lshift.spki.suiteb.cli;

import static org.junit.Assert.assertArrayEquals;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import net.lshift.spki.ParseException;
import net.lshift.spki.convert.ByteOpenable;
import net.lshift.spki.convert.Openable;

import org.apache.commons.io.IOUtils;
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
        OutputStream os = message.write();
        final byte[] messageBytes
            = "the magic words are squeamish ossifrage".getBytes();
        os.write(messageBytes);
        os.close();
        CLI.generateEncryptedSignedMessage(messageType,
            sPrivate, ePublic, message, packet);
        CLI.decryptSignedMessage(messageType,
            ePrivate, sPublic, packet, result);
        InputStream is = result.read();
        try {
            byte[] resultBytes = IOUtils.toByteArray(message.read());
            assertArrayEquals(messageBytes, resultBytes);
        } finally {
            is.close();
        }
    }
}
