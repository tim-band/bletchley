package net.lshift.spki.suiteb;

import static net.lshift.spki.convert.ConvertUtils.prettyPrint;
import static net.lshift.spki.sexpform.Create.list;
import static net.lshift.spki.suiteb.Cert.cert;
import static net.lshift.spki.suiteb.DigestSha384.digest;
import static net.lshift.spki.suiteb.InferenceEngineTest.checkMessage;
import static net.lshift.spki.suiteb.Signed.signed;

import java.io.IOException;
import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.convert.Converting;
import net.lshift.spki.convert.UsesSimpleMessage;
import net.lshift.spki.sexpform.Sexp;
import net.lshift.spki.sexpform.Slist;

import org.junit.Ignore;
import org.junit.Test;

public class NameBeanReorderTest extends UsesSimpleMessage {

    @Ignore
    @Test
    public void test() throws InvalidInputException, IOException  {
        final Action message = makeMessage();
        final PrivateSigningKey key = PrivateSigningKey.generate();
        // Reorder the public key
        final PublicSigningKey publicKey = key.getPublicKey();
        final Sexp pkSexp =
            Converting.write(PublicSigningKey.class, publicKey);

        prettyPrint(Sexp.class, pkSexp, System.out);
        final List<Sexp> coords
            = pkSexp.list().getSparts().get(0).list().getSparts();
        final Slist reversed = list("suiteb-p384-ecdsa-public-key",
            list("point", coords.get(1), coords.get(0)));

        prettyPrint(Sexp.class, reversed, System.out);
        final InferenceEngine engine = new InferenceEngine();
        engine.processTrusted(cert(digest(Sexp.class, reversed)));
        PublicSigningKey deserialized = ConvertUtils.C.read(
            PublicSigningKey.class, reversed);
        engine.process(deserialized);
        engine.process(signed(key, message));
        checkMessage(engine, message);
    }
}
