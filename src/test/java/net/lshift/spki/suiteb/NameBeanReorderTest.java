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
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.convert.UsesSimpleMessage;
import net.lshift.spki.sexpform.Sexp;
import net.lshift.spki.sexpform.Slist;

import org.junit.Test;

public class NameBeanReorderTest extends UsesSimpleMessage {
    @Test
    public void testRoundTrip() throws InvalidInputException, IOException  {
        final Sexp pkSexp =
            PrivateSigningKey.generate().getPublicKey().toSexp();

        prettyPrint(pkSexp, System.out);
        final List<Sexp> coords
            = pkSexp.list().getSparts().get(0).list().getSparts();
        final Slist reversed = list("suiteb-p384-ecdsa-public-key",
            list("point", coords.get(1), coords.get(0)));

        prettyPrint(reversed, System.out);
        final PublicSigningKey deserialized = ConvertUtils.C.read(
            PublicSigningKey.class, reversed);
        assertEquals(reversed, deserialized.toSexp());
        assertEquals(digest(reversed), deserialized.getKeyId());
    }

    @Test
    public void test() throws InvalidInputException, IOException  {
        final Action message = makeMessage();
        final PrivateSigningKey key = generateReversedKey();
        // Reorder the public key
        final PublicSigningKey publicKey = key.getPublicKey();
        final InferenceEngine engine = new InferenceEngine();
        engine.processTrusted(publicKey);
        engine.process(signed(key, message));
        checkMessage(engine, message);
    }

    protected PrivateSigningKey generateReversedKey() throws IOException, InvalidInputException {
        final Sexp sexp = PrivateSigningKey.generate().toSexp();
        prettyPrint(sexp, System.out);
        final List<Sexp> coords
            = sexp.list().getSparts()
            .get(0).list().getSparts()
            .get(0).list().getSparts()
            .get(0).list().getSparts();
        final Sexp reversedSexp = list("suiteb-p384-ecdsa-private-key",
            list("public-key",
                list("suiteb-p384-ecdsa-public-key",
                    list("point", coords.get(1), coords.get(0)))),
            sexp.list().getSparts().get(1));
        prettyPrint(reversedSexp, System.out);
        final PrivateSigningKey res = ConvertUtils.C.read(
            PrivateSigningKey.class, reversedSexp);
        assertEquals(reversedSexp, res.toSexp());
        assertEquals(reversedSexp.list().getSparts()
            .get(0).list().getSparts().get(0),
            res.getPublicKey().toSexp());
        return res;
    }
}
