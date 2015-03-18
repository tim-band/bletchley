package net.lshift.spki.suiteb.cli;

import static org.junit.Assert.assertArrayEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.UsesCatalog;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.convert.openable.OpenableUtils;

import org.junit.Test;

public class CliMultipleRecipientTest extends UsesCatalog
{
    @Test
    public void cliTest()
        throws IOException, InvalidInputException
    {
        final byte[] messageBytes
            = "the magic words are squeamish ossifrage".getBytes();

        final Openable sPrivate = new ByteOpenable();
        final Openable sPublic = new ByteOpenable();

        Cli.main(null, "genSigningKey", sPrivate);
        Cli.main(null, "getPublicSigningKey", sPrivate, sPublic);

        final List<Openable> ePrivates = new ArrayList<Openable>();
        final List<Openable> ePublics = new ArrayList<Openable>();
        for (int i = 0; i < 3; i++) {
            final Openable ePrivate = new ByteOpenable();
            final Openable ePublic = new ByteOpenable();

            Cli.main(null, "genEncryptionKey", ePrivate);
            Cli.main(null, "getPublicEncryptionKey", ePrivate, ePublic);
            ePrivates.add(ePrivate);
            ePublics.add(ePublic);
        }
        final Openable message = new ByteOpenable();
        OpenableUtils.writeBytes(message, messageBytes);
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
        Cli.main(null, "genEncryptedSignedMessage", encryptArgs);

        final Openable result = new ByteOpenable();
        for (final Openable ePrivate: ePrivates) {
            Cli.main(null,
                "decryptSignedMessage", ePrivate, sPublic, packet, result);
            final byte[] resultBytes = OpenableUtils.readBytes(result);
            assertArrayEquals(messageBytes, resultBytes);
        }
    }
}
