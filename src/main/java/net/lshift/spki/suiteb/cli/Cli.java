package net.lshift.spki.suiteb.cli;

import static net.lshift.spki.convert.OpenableUtils.read;
import static net.lshift.spki.convert.OpenableUtils.write;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

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
import net.lshift.spki.suiteb.sexpstructs.SequenceConversion;
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

    public static void prettyPrint(Openable file)
        throws IOException,
            ParseException {
        PrettyPrinter.prettyPrint(System.out, file.read());
    }

    public static void genEncryptionKey(Openable out)
        throws IOException {
        write(out, PrivateEncryptionKey.class,
                PrivateEncryptionKey.generate());
    }

    public static void getPublicEncryptionKey(Openable privk, Openable pubk)
        throws ParseException,
            IOException {
        final PrivateEncryptionKey privatek
                = read(PrivateEncryptionKey.class, privk);
        write(pubk, PublicEncryptionKey.class, privatek.getPublicKey());
    }

    public static void genSigningKey(Openable out)
        throws IOException {
        write(out, PrivateSigningKey.class, PrivateSigningKey.generate());
    }

    public static void getPublicSigningKey(Openable privk, Openable pubk)
        throws ParseException,
            IOException {
        final PrivateSigningKey privatek = read(PrivateSigningKey.class, privk);
        write(pubk, PublicSigningKey.class, privatek.getPublicKey());
    }

    public static void decryptSignedMessage(
        String messageType,
        PrivateEncryptionKey encryptionKey,
        PublicSigningKey signingKey,
        Openable packet,
        Openable out)
        throws ParseException,
            IOException {
        InferenceEngine inference = new InferenceEngine();
        inference.process(signingKey);
        inference.process(encryptionKey);
        inference.process(read(SequenceItem.class, packet));
        List<SequenceItem> signedBy
                = inference.getSignedBy(signingKey.getKeyId());
        if (signedBy.size() != 1) {
            throw new RuntimeException("Did not find exactly one signed message");
        }
        if (!(signedBy.get(0) instanceof SimpleMessage)) {
            throw new RuntimeException("Signed object was not message");
        }
        SimpleMessage message = (SimpleMessage) signedBy.get(0);
        if (!messageType.equals(message.type)) {
            throw new RuntimeException("Message was not of expected type");
        }
        OpenableUtils.writeBytes(out, message.content);
    }

    public static void decryptSignedMessage(
        String messageType,
        Openable ePrivate,
        Openable sPublic,
        Openable packet,
        Openable out)
        throws ParseException,
            IOException {
        PrivateEncryptionKey encryptionKey = read(PrivateEncryptionKey.class, ePrivate);
        PublicSigningKey signingKey = read(PublicSigningKey.class, sPublic);
        decryptSignedMessage(messageType, encryptionKey, signingKey, packet, out);
    }

    private static void genEncryptedSignedMessage(
        String messageType,
        Openable[] args)
        throws ParseException,
            IOException {
        List<SequenceItem> sequenceItems = new ArrayList<SequenceItem>();
        AesKey aesKey = AesKey.generateAESKey();
        for (int i = 2; i < args.length - 1; i++) {
            PublicEncryptionKey pKey = read(PublicEncryptionKey.class, args[i]);
            AesKey rKey = pKey.setupEncrypt(sequenceItems);
            sequenceItems.add(rKey.encrypt(aesKey));
        }

        List<SequenceItem> encryptedSequenceItems
                = new ArrayList<SequenceItem>();
        SimpleMessage message = new SimpleMessage(
                messageType, OpenableUtils.readBytes(args[1]));
        encryptedSequenceItems.add(message);
        PrivateSigningKey privateKey = read(PrivateSigningKey.class, args[0]);
        encryptedSequenceItems.add(privateKey.sign(message));

        sequenceItems.add(aesKey.encrypt(new Sequence(encryptedSequenceItems)));

        write(args[args.length - 1], Sequence.class, new Sequence(sequenceItems));
    }

    public static void main(String command, Openable... args)
        throws FileNotFoundException,
            ParseException,
            IOException {
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
        } else {
            throw new RuntimeException("Command not recognised: " + command);
        }
    }

    public static void serve(int port, final PrivateEncryptionKey encryptionKey, final PublicSigningKey signingKey) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), -1);
        server.createContext("/decryptAndVerify", new HttpHandler() {
            @Override
            public void handle(HttpExchange t) throws IOException {
                InputStream is = t.getRequestBody();
                ByteOpenable iso = new ByteOpenable();
                iso.write().write(IOUtils.toByteArray(is));
                OutputStream os = t.getResponseBody();
                if (!t.getRequestMethod().equals("PUT")) {
                    writeResponse(t, os, 400, "Expected PUT request".getBytes("ASCII"));
                    return;
                }
                ByteOpenable oso = new ByteOpenable();
                try {
                    decryptSignedMessage(CLI_MESSAGE, encryptionKey, signingKey, iso, oso);
                    byte[] ans = IOUtils.toByteArray(oso.read());
                    writeResponse(t, os, 200, ans);
                } catch (ParseException e) {
                    writeResponse(t, os, 400,
                            ("Could not decrypt and verify: " + e.getMessage()).getBytes("ascii"));
                }
            }
            void writeResponse(HttpExchange t, OutputStream os, int responseCode, byte[] ans) throws IOException {
                t.sendResponseHeaders(responseCode, ans.length);
                os.write(ans);
                os.close();
            }
        });
        server.setExecutor(null); // creates a default executor
        server.start();

    }

    public static void main(String[] args) {
        String command = "<no valid command>";
        try {
            int i = 0;
            command = args[i++];
            if (command.equals("server")) {
                final int port = Integer.parseInt(args[i++]);
                final PrivateEncryptionKey encryptionKey = read(PrivateEncryptionKey.class, new FileOpenable(new File(args[i++])));
                final PublicSigningKey signingKey = read(PublicSigningKey.class, new FileOpenable(new File(args[i++])));
                serve(port, encryptionKey, signingKey);
            } else {
                List<Openable> openables = new ArrayList<Openable>();
                for (;i < args.length; i++) {
                    openables.add(new FileOpenable(new File(args[i])));
                }
                main(command, openables.toArray(new Openable[0]));
            }

        } catch (Exception ex) {
            System.err.println("Could not '" + command + "':");
            ex.printStackTrace();
            System.exit(2);
        }
    }

    static {
        SequenceConversion.ensureInstalled();
    }
}
