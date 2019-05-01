package net.lshift.spki.suiteb.cli;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Permission;
import java.util.regex.Pattern;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.convert.UsesCatalog;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.convert.openable.FileOpenable;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.convert.openable.OpenableUtils;

import org.apache.commons.io.IOUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class CliTest extends UsesCatalog
{
    private static final Pattern FINGERPRINT_OUTPUT
        = Pattern.compile("[a-z]{1,6}-[a-z]{1,6}-[a-z]{1,6}/[a-z]{1,6}-[a-z]{1,6}-[a-z]{1,6}/[a-z]{1,6}-[a-z]{1,6}-[a-z]{1,6}/[a-z]{1,6}-[a-z]{1,6}-[a-z]{1,6}/[a-z]{1,6}-[a-z]{1,6}-[a-z]{1,6}\n");
    private SecurityManager securityManager;
    
    static class ExitException extends SecurityException {
        public ExitException(int status) {
            this.status = status;
        }
        private static final long serialVersionUID = 1L;
        public final int status;

    }
    
    private static class NoExitSecurityManager extends SecurityManager {
        @Override
        public void checkPermission(Permission perm) {
            // allow anything.
        }

        @Override
        public void checkPermission(Permission perm, Object context) {
            // allow anything.
        }

        @Override
        public void checkExit(int status) {
            super.checkExit(status);
            throw new ExitException(status);
        }
    }

    @Before
    public void setUp() {
        securityManager = System.getSecurityManager();
        System.setSecurityManager(new NoExitSecurityManager());
    }
    
    @After
    public void tearDown() {
        System.setSecurityManager(securityManager);
    }
    
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
    public void mainWithStdoutTest() throws IOException, ParseException {
        PrintStream originalOut = System.out;
        Path workDir = Files.createTempDirectory(this.getClass().getName());
        workDir.toFile().deleteOnExit();
        Path signingKeyPath = workDir.resolve("signing-private-key.spki");

        Cli.main(new String [] { "genSigningKey", signingKeyPath.toString() });

        final Openable prettyPrinted = new ByteOpenable();
        System.setOut(new PrintStream(prettyPrinted.write()));
        try {
            Cli.main(new String [] { "prettyPrint", signingKeyPath.toString() });
        } finally {
            System.setOut(originalOut);
        }
        
        FileOpenable canonical = new FileOpenable(signingKeyPath.toFile());
        ByteOpenable refPrettyPrinted = new ByteOpenable();
        Cli.prettyPrintToFile(canonical, refPrettyPrinted);
        
        assertTrue(IOUtils.contentEquals(prettyPrinted.read(), refPrettyPrinted.read()));
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
    
    @Test(expected=IllegalArgumentException.class)
    public void testUnknownCommand() throws IOException, InvalidInputException {
        Cli.main(null, "unknown");
    }
    
    @Test(expected=ExitException.class)
    public void testUnknownCommandLogging()  {
        Cli.main(new String [] { "unknown" });
    }
    
}
