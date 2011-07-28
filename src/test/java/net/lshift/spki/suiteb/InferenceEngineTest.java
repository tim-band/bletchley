package net.lshift.spki.suiteb;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.util.List;

import net.lshift.spki.convert.ResetsRegistry;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

import org.junit.Test;

public class InferenceEngineTest extends ResetsRegistry {
    @Test
    public void emptyListIfSignerHasDoneNothing() {
        PrivateSigningKey key = PrivateSigningKey.generate();
        InferenceEngine engine = new InferenceEngine();
        List<SequenceItem> res = engine.getSignedBy(key.getPublicKey().getKeyId());
        assertThat(res.size(), is(equalTo(0)));
    }
}
