package net.lshift.spki.suiteb.fingerprint;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import net.lshift.spki.sexpform.Create;
import net.lshift.spki.sexpform.Sexp;

import org.junit.Test;

public class FingerprintTest {
    // FIXME ideas for more meaningful tests welcome
    @Test
    public void canGenerateFingerprint() {
        Sexp testSexp = Create.list("fooble");
        String fingerprint
            = FingerprintUtils.getFingerprint(Sexp.class, testSexp);
        assertNotNull(fingerprint);
        System.out.println(fingerprint);
        assertEquals(fingerprint,
            FingerprintUtils.getFingerprint(Sexp.class, testSexp));
    }
}
