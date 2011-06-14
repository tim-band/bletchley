package net.lshift.spki.suiteb.cli;

import static net.lshift.spki.convert.OpenableUtils.read;
import static net.lshift.spki.convert.OpenableUtils.write;

import java.io.*;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.convert.ByteOpenable;
import net.lshift.spki.convert.FileOpenable;
import net.lshift.spki.convert.Openable;
import net.lshift.spki.convert.OpenableUtils;
import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.InferenceEngine;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.PublicSigningKey;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;

import org.apache.commons.io.IOUtils;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

/**
 * Command line interface to crypto functions
 */
public class Cli {
    static final String CLI_MESSAGE = Cli.class.toString();

    public static void prettyPrint(final Openable file)
        throws IOException,
            ParseException {
        PrettyPrinter.prettyPrint(System.out, file.read());
    }

    public static void genEncryptionKey(final Openable out)
        throws IOException {
        write(PrivateEncryptionKey.class, PrivateEncryptionKey.generate(),
            out);
    }

    public static void getPublicEncryptionKey(final Openable privk, final Openable pubk)
        throws IOException, InvalidInputException {
        final PrivateEncryptionKey privatek
            = read(PrivateEncryptionKey.class, privk);
        write(PublicEncryptionKey.class, privatek.getPublicKey(), pubk);
    }

    public static void genSigningKey(final Openable out)
        throws IOException {
        write(PrivateSigningKey.class, PrivateSigningKey.generate(), out);
    }

    public static void getPublicSigningKey(final Openable privk, final Openable pubk)
        throws IOException, InvalidInputException {
        final PrivateSigningKey privatek = read(PrivateSigningKey.class, privk);
        write(PublicSigningKey.class, privatek.getPublicKey(), pubk);
    }

    public static void decryptSignedMessage(
        final String messageType,
        final PrivateEncryptionKey encryptionKey,
        final PublicSigningKey signingKey,
        final Openable packet,
        final Openable out)
        throws IOException, InvalidInputException {
        final InferenceEngine inference = new InferenceEngine();
        inference.process(signingKey);
        inference.process(encryptionKey);
        inference.process(read(SequenceItem.class, packet));
        final List<SequenceItem> signedBy
            = inference.getSignedBy(signingKey.getKeyId());
        if (signedBy.size() != 1) {
            throw new RuntimeException("Did not find exactly one signed message");
        }
        if (!(signedBy.get(0) instanceof SimpleMessage)) {
            throw new RuntimeException("Signed object was not message");
        }
        final SimpleMessage message = (SimpleMessage) signedBy.get(0);
        if (!messageType.equals(message.type)) {
            throw new RuntimeException("Message was not of expected type");
        }
        OpenableUtils.writeBytes(message.content, out);
    }

    public static void decryptSignedMessage(
        final String messageType,
        final Openable ePrivate,
        final Openable sPublic,
        final Openable packet,
        final Openable out)
        throws IOException, InvalidInputException {
        final PrivateEncryptionKey encryptionKey = read(PrivateEncryptionKey.class, ePrivate);
        final PublicSigningKey signingKey = read(PublicSigningKey.class, sPublic);
        decryptSignedMessage(messageType, encryptionKey, signingKey, packet, out);
    }

    public static void genEncryptedSignedMessage(
        final String messageType,
        final Openable[] args)
        throws IOException, InvalidInputException {
        final List<SequenceItem> sequenceItems = new ArrayList<SequenceItem>();
        final AesKey aesKey = AesKey.generateAESKey();
        for (int i = 2; i < args.length - 1; i++) {
            final PublicEncryptionKey pKey = read(PublicEncryptionKey.class, args[i]);
            final AesKey rKey = pKey.setupEncrypt(sequenceItems);
            sequenceItems.add(rKey.encrypt(aesKey));
        }

        final List<SequenceItem> encryptedSequenceItems
            = new ArrayList<SequenceItem>();
        final SimpleMessage message = new SimpleMessage(
            messageType, OpenableUtils.readBytes(args[1]));
        final PrivateSigningKey privateKey = read(PrivateSigningKey.class, args[0]);
        encryptedSequenceItems.add(privateKey.sign(message));
        encryptedSequenceItems.add(message);

        sequenceItems.add(aesKey.encrypt(new Sequence(encryptedSequenceItems)));

        write(Sequence.class, new Sequence(sequenceItems), args[args.length - 1]);
    }

    public static void speedTest() throws InvalidInputException {
        new SpeedTester().speedTest();
    }

    public static void main(final String command, final Openable... args)
        throws FileNotFoundException,
            IOException, InvalidInputException {
        if ("prettyPrint".equals(command)) {
            prettyPrint(args[0]);
        } else if ("genSigningKey".equals(command)) {
            genSigningKey(args[0]);
        } else if ("genEncryptionKey".equals(command)) {
            genEncryptionKey(args[0]);
        } else if ("getPublicSigningKey".equals(command)) {
            getPublicSigningKey(args[0], args[1]);
        } else if ("getPublicEncryptionKey".equals(command)) {
            getPublicEncryptionKey(args[0], args[1]);
        } else if ("decryptSignedMessage".equals(command)) {
            decryptSignedMessage(CLI_MESSAGE,
                args[0], args[1], args[2], args[3]);
        } else if ("genEncryptedSignedMessage".equals(command)) {
            genEncryptedSignedMessage(CLI_MESSAGE, args);
        } else if ("speedTest".equals(command)) {
            speedTest();
        } else {
            throw new RuntimeException("Command not recognised: " + command);
        }
    }

    public static void serve(final int port, final String messageType, final PrivateEncryptionKey encryptionKey, final PublicSigningKey signingKey) throws Exception {
        final HttpServer server = HttpServer.create(new InetSocketAddress(port), -1);
        server.createContext("/decryptAndVerify", new HttpHandler() {
            @Override
            public void handle(final HttpExchange t) throws IOException {
                final InputStream is = t.getRequestBody();
                final ByteOpenable iso = new ByteOpenable();
                iso.write().write(IOUtils.toByteArray(is));
                final OutputStream os = t.getResponseBody();
                if (!t.getRequestMethod().equals("POST")) {
                    writeResponse(t, os, 400, "Expected POST request".getBytes("ASCII"));
                    return;
                }
                final ByteOpenable oso = new ByteOpenable();
                try {
                    decryptSignedMessage(messageType, encryptionKey, signingKey, iso, oso);
                    final byte[] ans = IOUtils.toByteArray(oso.read());
                    writeResponse(t, os, 200, ans);
                } catch (final Exception e) {
                    final StringWriter sw = new StringWriter();
                    e.printStackTrace(new PrintWriter(sw));
                    writeResponse(t, os, 400,
                            ("Could not decrypt and verify: " +
                                    e.getClass().getName() + e.getMessage() + "\n" + sw.toString()).getBytes("ascii"));
                }
            }
            void writeResponse(final HttpExchange t, final OutputStream os, final int responseCode, final byte[] ans) throws IOException {
                t.sendResponseHeaders(responseCode, ans.length);
                os.write(ans);
                os.close();
            }
        });
        server.setExecutor(null); // creates a default executor
        server.start();
        System.out.println("Running on port " + port);
        System.out.flush();
    }

    public static void main(final String[] args) {
        String command = "<no valid command>";
        try {
            int i = 0;
            command = args[i++];
            if (command.equals("server")) {
                final int port = Integer.parseInt(args[i++]);
                final String messageType = args[i++];
                final PrivateEncryptionKey encryptionKey = read(PrivateEncryptionKey.class, new FileOpenable(new File(args[i++])));
                final PublicSigningKey signingKey = read(PublicSigningKey.class, new FileOpenable(new File(args[i++])));
                serve(port, messageType, encryptionKey, signingKey);
            } else {
                final List<Openable> openables = new ArrayList<Openable>();
                for (;i < args.length; i++) {
                    openables.add(new FileOpenable(new File(args[i])));
                }
                main(command, openables.toArray(new Openable[0]));
            }

        } catch (final Exception ex) {
            System.err.println("Could not '" + command + "':");
            ex.printStackTrace();
            System.exit(2);
        }
    }
}
