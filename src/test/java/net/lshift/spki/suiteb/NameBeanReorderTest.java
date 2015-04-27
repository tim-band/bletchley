package net.lshift.spki.suiteb;

import static net.lshift.spki.convert.ConvertUtils.prettyPrint;
import static net.lshift.spki.sexpform.Create.list;
import static net.lshift.spki.suiteb.DigestSha384.digest;
import static net.lshift.spki.suiteb.InferenceEngineTest.checkMessage;
import static net.lshift.spki.suiteb.Signed.signed;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.UsesSimpleMessage;
import net.lshift.spki.sexpform.Sexp;
import net.lshift.spki.sexpform.Slist;

import org.junit.Test;

public class NameBeanReorderTest extends UsesSimpleMessage {
    @Test
    public void testRoundTrip() throws InvalidInputException, IOException  {
        PrivateSigningKey originalKey = PrivateSigningKey.generate();
        final Sexp originalSexp = originalKey.getPublicKey().toSexp();

        prettyPrint(originalSexp, System.out);
        final List<Sexp> coords = originalSexp.list().getSparts().get(0).list().getSparts();
        final Slist reversedSexp = list("suiteb-p384-ecdsa-public-key",
            list("point", coords.get(1), coords.get(0)));

        prettyPrint(reversedSexp, System.out);
        final PublicSigningKey deserialized = getReadInfo().read(
            PublicSigningKey.class, reversedSexp);
        final Sexp recoveredSexp = deserialized.toSexp();
        assertEquals(originalSexp, recoveredSexp);
        assertEquals(digest(recoveredSexp), deserialized.getKeyId());
    }

    @Test
    public void test() throws InvalidInputException, IOException  {
        final Action message = makeMessage();
        final PrivateSigningKey key = generateReversedKey();
        // Reorder the public key
        final PublicSigningKey publicKey = key.getPublicKey();
        final InferenceEngine engine = newEngine();
        engine.processTrusted(publicKey);
        engine.process(signed(key, message));
        checkMessage(engine, message);
    }

    protected PrivateSigningKey generateReversedKey() throws IOException, InvalidInputException {
        PrivateSigningKey originalKey = PrivateSigningKey.generate();
        final Sexp originalSexp = originalKey.toSexp();
        prettyPrint(originalSexp, System.out);
        final List<Sexp> coords
            = originalSexp.list().getSparts()
                .get(1).list().getSparts()
                .get(0).list().getSparts()
                .get(0).list().getSparts();
        final Sexp reversedSexp = list("suiteb-p384-ecdsa-private-key",
                list("public-key",
                        list("suiteb-p384-ecdsa-public-key",
                                list("point", coords.get(1), coords.get(0)))),
                originalSexp.list().getSparts().get(0));
        prettyPrint(reversedSexp, System.out);
        final PrivateSigningKey reversedKey = getReadInfo().read(
            PrivateSigningKey.class, reversedSexp);
        final Sexp recoveredSexp = reversedKey.toSexp();
        assertEquals(originalSexp, recoveredSexp);
        assertEquals(recoveredSexp.list().getSparts()
                        .get(1).list().getSparts().get(0),
                reversedKey.getPublicKey().toSexp());
        return reversedKey;
    }
}
