package net.lshift.spki.suiteb.cli;

import static org.junit.Assert.assertArrayEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.ParseException;
import net.lshift.spki.convert.ByteOpenable;
import net.lshift.spki.convert.Openable;
import net.lshift.spki.convert.OpenableUtils;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Test;

public class CLIMultipleRecipientTest
{
    @Test
    public void cliTest()
        throws InvalidCipherTextException,
            ParseException,
            IOException
    {
        final byte[] messageBytes
            = "the magic words are squeamish ossifrage".getBytes();

        Openable sPrivate = new ByteOpenable();
        Openable sPublic = new ByteOpenable();

        CLI.main("genSigningKey", sPrivate);
        CLI.main("getPublicSigningKey", sPrivate, sPublic);

        List<Openable> ePrivates = new ArrayList<Openable>();
        List<Openable> ePublics = new ArrayList<Openable>();
        for (int i = 0; i < 3; i++) {
            Openable ePrivate = new ByteOpenable();
            Openable ePublic = new ByteOpenable();

            CLI.genEncryptionKey(ePrivate);
            CLI.getPublicEncryptionKey(ePrivate, ePublic);
            ePrivates.add(ePrivate);
            ePublics.add(ePublic);
        }
        Openable message = new ByteOpenable();
        OpenableUtils.writeBytes(message, messageBytes);
        Openable[] encryptArgs = new Openable[ePublics.size() + 3];
        int i = 0;
        encryptArgs[i++] = sPrivate;
        encryptArgs[i++] = message;
        for (Openable key: ePublics) {
            encryptArgs[i++] = key;
        }
        Openable packet = new ByteOpenable();
        encryptArgs[i++] = packet;
        assert(i == encryptArgs.length);
        CLI.main("genEncryptedSignedMRMessage", encryptArgs);

        Openable result = new ByteOpenable();
        for (Openable ePrivate: ePrivates) {
            CLI.main("decryptSignedMRMessage",
                ePrivate, sPublic, packet, result);
            byte[] resultBytes = OpenableUtils.readBytes(result);
            assertArrayEquals(messageBytes, resultBytes);
        }
    }
}
