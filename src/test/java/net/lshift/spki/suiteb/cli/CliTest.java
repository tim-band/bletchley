package net.lshift.spki.suiteb.cli;

import static org.junit.Assert.assertArrayEquals;

import java.io.IOException;

import net.lshift.spki.ParseException;
import net.lshift.spki.convert.ByteOpenable;
import net.lshift.spki.convert.Openable;
import net.lshift.spki.convert.OpenableUtils;

import org.junit.Test;

public class CliTest
{
    @Test
    public void cliTest()
        throws ParseException,
            IOException
    {
        final byte[] messageBytes
            = "the magic words are squeamish ossifrage".getBytes();
        Openable sPrivate = new ByteOpenable();
        Openable sPublic = new ByteOpenable();
        Openable ePrivate = new ByteOpenable();
        Openable ePublic = new ByteOpenable();
        Openable message = new ByteOpenable();
        Openable packet = new ByteOpenable();
        Openable result = new ByteOpenable();

        Cli.main("genSigningKey", sPrivate);
        Cli.main("getPublicSigningKey", sPrivate, sPublic);
        Cli.main("genEncryptionKey", ePrivate);
        Cli.main("getPublicEncryptionKey", ePrivate, ePublic);

        OpenableUtils.writeBytes(message, messageBytes);
        Cli.main("genEncryptedSignedMessage",
            sPrivate, message, ePublic, packet);
        Cli.main("decryptSignedMessage",
            ePrivate, sPublic, packet, result);
        byte[] resultBytes = OpenableUtils.readBytes(result);
        assertArrayEquals(messageBytes, resultBytes);
    }
}
