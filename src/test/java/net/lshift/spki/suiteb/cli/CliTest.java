package net.lshift.spki.suiteb.cli;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.util.regex.Pattern;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ResetsRegistry;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.convert.openable.OpenableUtils;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

public class CliTest extends ResetsRegistry
{
    private static final Pattern FINGERPRINT_OUTPUT
        = Pattern.compile("[a-z]{1,6}-[a-z]{1,6}-[a-z]{1,6}/[a-z]{1,6}-[a-z]{1,6}-[a-z]{1,6}/[a-z]{1,6}-[a-z]{1,6}-[a-z]{1,6}/[a-z]{1,6}-[a-z]{1,6}-[a-z]{1,6}/[a-z]{1,6}-[a-z]{1,6}-[a-z]{1,6}\n");

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

        Cli.main(null, "genSigningKey", sPrivate);
        Cli.main(null, "getPublicSigningKey", sPrivate, sPublic);
        Cli.main(null, "genEncryptionKey", ePrivate);
        Cli.main(null, "getPublicEncryptionKey", ePrivate, ePublic);

        OpenableUtils.writeBytes(message, messageBytes);
        Cli.main(null,
            "genEncryptedSignedMessage", sPrivate, message, ePublic, packet);
        Cli.main(null,
            "decryptSignedMessage", ePrivate, sPublic, packet, result);
        final byte[] resultBytes = OpenableUtils.readBytes(result);
        assertArrayEquals(messageBytes, resultBytes);
    }

    @Test
    public void prettyPrintTest() throws FileNotFoundException, IOException, InvalidInputException {
        final Openable sPrivate = new ByteOpenable();
        final Openable pp = new ByteOpenable();
        final Openable canonical = new ByteOpenable();

        Cli.main(null, "genSigningKey", sPrivate);
        Cli.main(null, "prettyPrintToFile", sPrivate, pp);
        Cli.main(null, "canonical", pp, canonical);
        assertTrue(IOUtils.contentEquals(sPrivate.read(), canonical.read()));
    }

    @Test
    public void signingFingerprintTest()
        throws IOException, InvalidInputException
    {
        final Openable sPrivate = new ByteOpenable();
        Cli.main(null, "genSigningKey", sPrivate);
        final String privFingerprint = getTextOut("fingerprintPrivateSigningKey", sPrivate);
        assertTrue(isFingerprint(privFingerprint));
        final Openable sPublic = new ByteOpenable();
        Cli.main(null, "getPublicSigningKey", sPrivate, sPublic);
        final String pubFingerprint = getTextOut("fingerprintPublicSigningKey", sPublic);
        assertEquals(privFingerprint, pubFingerprint);
    }

    @Test
    public void encryptionFingerprintTest()
        throws IOException, InvalidInputException
    {
        final Openable sPrivate = new ByteOpenable();
        Cli.main(null, "genEncryptionKey", sPrivate);
        final String privFingerprint = getTextOut("fingerprintPrivateEncryptionKey", sPrivate);
        assertTrue(isFingerprint(privFingerprint));
        final Openable sPublic = new ByteOpenable();
        Cli.main(null, "getPublicEncryptionKey", sPrivate, sPublic);
        final String pubFingerprint = getTextOut("fingerprintPublicEncryptionKey", sPublic);
        assertEquals(privFingerprint, pubFingerprint);
    }

    private static String getTextOut(final String command, final Openable... args)
                    throws IOException, InvalidInputException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        Cli.main(new PrintStream(out), command, args);
        return out.toString("UTF-8");
    }

    private static boolean isFingerprint(final String pubFingerprint) {
        return FINGERPRINT_OUTPUT.matcher(pubFingerprint).matches();
    }
}
