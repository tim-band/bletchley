package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.suiteb.Cert.cert;
import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.io.PrintWriter;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.convert.openable.OpenableUtils;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicSigningKey;
import net.lshift.spki.suiteb.SequenceItem;

import org.junit.Test;

public class TestLoop {
    @Test
    public void test() throws IOException, InvalidInputException {
        PrivateEncryptionKey decryptionKey = PrivateEncryptionKey.generate();
        PrivateSigningKey signingKey = PrivateSigningKey.generate();
        ByteOpenable acl = new ByteOpenable();
        PublicSigningKey publicKey = signingKey.getPublicKey();
        OpenableUtils.write(SequenceItem.class, sequence(
                decryptionKey,
                publicKey,
                cert(publicKey.getKeyId())
            ), acl);

        Service service = new Service("http", 80);
        ByteOpenable target = new ByteOpenable();
        WriteService.writeService(signingKey, decryptionKey.getPublicKey(),
            target, service);
        Service readBack = ReadService.readService(acl, target);
        assertThat(readBack.name, is(service.name));
        assertThat(readBack.port, is(service.port));
        PrettyPrinter.prettyPrint(
            new PrintWriter(System.out), target.read());
    }
}
