package net.lshift.spki.suiteb.cli;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Permission;
import java.text.MessageFormat;
import java.util.regex.Pattern;

import net.lshift.spki.InvalidInputException;
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
            super(MessageFormat.format("Exit with status {0}", status));
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
        final Openable sPublic = new ByteOpenable();
        final Openable pp = new ByteOpenable();
        final Openable canonical = new ByteOpenable();

        Cli.main(null, "genSigningKey", sPrivate);
        Cli.main(null, "getPublicSigningKey", sPrivate, sPublic);
        Cli.main(null, "prettyPrintToFile", sPublic, pp);
        Cli.main(null, "canonical", pp, canonical);
        assertTrue(IOUtils.contentEquals(sPublic.read(), canonical.read()));
    }

    /**
     * This test demonstrates that commands that should
     * write to stdout actually do, by capturing the output and verifying it
     * is as expected. We use the example of pretty printing a private signing key.
     * This is overkill, but satisfies our code coverage rules for new code.
     * @throws IOException
     * @throws InvalidInputException 
     */
    @Test
    public void mainWithStdoutTest() throws IOException, InvalidInputException {
        PrintStream originalOut = System.out;
        Path workDir = Files.createTempDirectory(this.getClass().getName());
        workDir.toFile().deleteOnExit();
        Path signingKeyPath = workDir.resolve("signing-private-key.spki");
        Path publicSigningKeyPath = workDir.resolve("signing-public-key.spki");

        // Generate a signing key, for later pretty printing
        Cli.main(new String [] { "genSigningKey", signingKeyPath.toString() });
        Cli.main(new String [] { "getPublicSigningKey", signingKeyPath.toString(), publicSigningKeyPath.toString() });

        final Openable prettyPrinted = new ByteOpenable();
        try(PrintStream out = new PrintStream(prettyPrinted.write())) {
            System.setOut(out);
            try {
                Cli.main(new String [] { "prettyPrint", publicSigningKeyPath.toString() });
            } finally {
                System.setOut(originalOut);
            }
        }

        FileOpenable canonical = new FileOpenable(publicSigningKeyPath.toFile());
        ByteOpenable refPrettyPrinted = new ByteOpenable();
        // Pretty print directly, so we can compare the results
        Cli.prettyPrintToFile(canonical, refPrettyPrinted);

        // Compare our directly generated pretty printed key with the one
        // written to stdout
        assertEquals(
                IOUtils.toString(new InputStreamReader(refPrettyPrinted.read())),
                IOUtils.toString(new InputStreamReader(prettyPrinted.read())));
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
