package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.convert.openable.OpenableUtils.write;
import static net.lshift.spki.suiteb.Cert.cert;
import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static net.lshift.spki.suiteb.Signed.signed;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Date;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.suiteb.Cert;
import net.lshift.spki.suiteb.InvalidOnOrAfter;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicSigningKey;
import net.lshift.spki.suiteb.SequenceItem;

import org.junit.Test;

public class TestLoop {
    private ByteOpenable writeSequence(SequenceItem... items) throws IOException {
        ByteOpenable res = new ByteOpenable();
        write(SequenceItem.class, sequence(items), res);
        return res;
    }

    @Test
    public void test() throws IOException, InvalidInputException {
        PrivateEncryptionKey decryptionKey = PrivateEncryptionKey.generate();
        PrivateSigningKey masterKey = PrivateSigningKey.generate();
        PublicSigningKey publicKey = masterKey.getPublicKey();
        ByteOpenable acl = writeSequence(
            decryptionKey,
            cert(publicKey.getKeyId())
        );

        PrivateSigningKey subKey = PrivateSigningKey.generate();
        Cert myCert = cert(subKey.getPublicKey().getKeyId(),
            new InvalidOnOrAfter(new Date(System.currentTimeMillis() + 1000)));
        ByteOpenable extra = writeSequence(
            publicKey,
            subKey.getPublicKey(),
            masterKey.sign(myCert),
            signed(myCert));

        Service service = new Service("http", 80);
        ByteOpenable target = new ByteOpenable();
        WriteService.writeService(subKey, extra, decryptionKey.getPublicKey(),
            target, service);
        Service readBack = ReadService.readService(acl, target);
        assertThat(readBack.name, is(service.name));
        assertThat(readBack.port, is(service.port));
        PrettyPrinter.prettyPrint(
            new PrintWriter(System.out), target.read());
    }
}
