package net.lshift.spki.suiteb.cli;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import java.io.FileNotFoundException;
import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ResetsRegistry;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.convert.openable.OpenableUtils;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

public class CliTest extends ResetsRegistry
{
    @Test
    public void cliTest()
        throws IOException, InvalidInputException
    {
        final byte[] messageBytes
            = "the magic words are squeamish ossifrage".getBytes();
        final Openable sPrivate = new ByteOpenable();
        final Openable sPublic = new ByteOpenable();
        final Openable ePrivate = new ByteOpenable();
        final Openable ePublic = new ByteOpenable();
        final Openable message = new ByteOpenable();
        final Openable packet = new ByteOpenable();
        final Openable result = new ByteOpenable();

        Cli.main("genSigningKey", sPrivate);
        Cli.main("getPublicSigningKey", sPrivate, sPublic);
        Cli.main("genEncryptionKey", ePrivate);
        Cli.main("getPublicEncryptionKey", ePrivate, ePublic);

        OpenableUtils.writeBytes(messageBytes, message);
        Cli.main("genEncryptedSignedMessage",
            sPrivate, message, ePublic, packet);
        Cli.main("decryptSignedMessage",
            ePrivate, sPublic, packet, result);
        final byte[] resultBytes = OpenableUtils.readBytes(result);
        assertArrayEquals(messageBytes, resultBytes);
    }

    @Test
    public void prettyPrintTest() throws FileNotFoundException, IOException, InvalidInputException {
        final Openable sPrivate = new ByteOpenable();
        final Openable pp = new ByteOpenable();
        final Openable canonical = new ByteOpenable();

        Cli.main("genSigningKey", sPrivate);
        Cli.main("prettyPrintToFile", sPrivate, pp);
        Cli.main("canonical", pp, canonical);
        assertTrue(IOUtils.contentEquals(sPrivate.read(), canonical.read()));
    }
}
