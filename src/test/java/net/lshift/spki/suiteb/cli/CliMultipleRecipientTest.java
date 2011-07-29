package net.lshift.spki.suiteb.cli;

import static org.junit.Assert.assertArrayEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ByteOpenable;
import net.lshift.spki.convert.Openable;
import net.lshift.spki.convert.OpenableUtils;
import net.lshift.spki.convert.ResetsRegistry;

import org.junit.Test;

public class CliMultipleRecipientTest extends ResetsRegistry
{
    @Test
    public void cliTest()
        throws IOException, InvalidInputException
    {
        final byte[] messageBytes
            = "the magic words are squeamish ossifrage".getBytes();

        final Openable sPrivate = new ByteOpenable();
        final Openable sPublic = new ByteOpenable();

        Cli.main("genSigningKey", sPrivate);
        Cli.main("getPublicSigningKey", sPrivate, sPublic);

        final List<Openable> ePrivates = new ArrayList<Openable>();
        final List<Openable> ePublics = new ArrayList<Openable>();
        for (int i = 0; i < 3; i++) {
            final Openable ePrivate = new ByteOpenable();
            final Openable ePublic = new ByteOpenable();

            Cli.main("genEncryptionKey", ePrivate);
            Cli.main("getPublicEncryptionKey", ePrivate, ePublic);
            ePrivates.add(ePrivate);
            ePublics.add(ePublic);
        }
        final Openable message = new ByteOpenable();
        OpenableUtils.writeBytes(messageBytes, message);
        final Openable[] encryptArgs = new Openable[ePublics.size() + 3];
        int i = 0;
        encryptArgs[i++] = sPrivate;
        encryptArgs[i++] = message;
        for (final Openable key: ePublics) {
            encryptArgs[i++] = key;
        }
        final Openable packet = new ByteOpenable();
        encryptArgs[i++] = packet;
        assert i == encryptArgs.length;
        Cli.main("genEncryptedSignedMessage", encryptArgs);

        final Openable result = new ByteOpenable();
        for (final Openable ePrivate: ePrivates) {
            Cli.main("decryptSignedMessage",
                ePrivate, sPublic, packet, result);
            final byte[] resultBytes = OpenableUtils.readBytes(result);
            assertArrayEquals(messageBytes, resultBytes);
        }
    }
}
