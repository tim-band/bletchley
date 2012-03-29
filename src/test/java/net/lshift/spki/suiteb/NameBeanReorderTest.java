package net.lshift.spki.suiteb;

import static net.lshift.spki.sexpform.Create.list;
import static net.lshift.spki.suiteb.InferenceEngineTest.checkMessage;
import static net.lshift.spki.suiteb.Signed.signed;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

import net.lshift.spki.CanonicalSpkiInputStream;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.convert.UsesSimpleMessage;
import net.lshift.spki.sexpform.Sexp;
import net.lshift.spki.sexpform.Slist;
import net.lshift.spki.suiteb.simplemessage.SimpleMessage;

import org.junit.Test;

public class NameBeanReorderTest extends UsesSimpleMessage {

    @Test
    public void test() throws InvalidInputException, IOException  {
        final Action message = SimpleMessage.makeMessage(this.getClass());
        final PrivateSigningKey key = PrivateSigningKey.generate();
        // Reorder the public key
        final PublicSigningKey publicKey = key.getPublicKey();
        final Sexp pkSexp = ConvertUtils.fromBytes(Sexp.class,
            ConvertUtils.toBytes(PublicSigningKey.class, publicKey));
        ConvertUtils.prettyPrint(Sexp.class, pkSexp, System.out);
        final List<Sexp> coords = ((Slist)((Slist)pkSexp).getSparts().get(0)).getSparts();
        final Slist reversed = list("suiteb-p384-ecdsa-public-key",
            list("point", coords.get(1), coords.get(0)));

        ConvertUtils.prettyPrint(Sexp.class, reversed, System.out);
        final InferenceEngine engine = new InferenceEngine();
        engine.processTrusted(new Cert(
            DigestSha384.digest(Sexp.class, reversed),
            Collections.<Condition>emptyList()));
        engine.process(
            new CanonicalSpkiInputStream(
                new ByteArrayInputStream(
                    ConvertUtils.toBytes(Sexp.class, reversed))));
        engine.process(publicKey);
        engine.process(key.sign(message));
        engine.process(signed(message));
        checkMessage(engine, message);
    }
}
