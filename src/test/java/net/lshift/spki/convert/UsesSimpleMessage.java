package net.lshift.spki.convert;

import static net.lshift.spki.suiteb.SequenceUtils.action;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.nio.charset.StandardCharsets;

import org.junit.Assert;

import com.google.protobuf.ByteString;
import com.google.protobuf.Message;

import net.lshift.bletchley.suiteb.proto.SimpleMessageProto;
import net.lshift.bletchley.suiteb.proto.SimpleMessageProto.SimpleMessage;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.InferenceEngine;
import net.lshift.spki.suiteb.SequenceItem;
import net.lshift.spki.suiteb.SequenceItemConverter;

public class UsesSimpleMessage extends UsesCatalog {
    public static final SequenceItemConverter parser = new SequenceItemConverter(SimpleMessage.class);
    private static final ByteString CONTENT = ByteString.copyFrom(
            "The magic words are squeamish ossifrage".getBytes(StandardCharsets.US_ASCII));

    public <T extends SequenceItem> T roundTrip(final Class<T> clazz, final T o) {
        return roundTrip(clazz, o, parser);
    }

    protected Action makeMessage() {
        return action(
                SimpleMessageProto.SimpleMessage.newBuilder()
                .setType(this.getClass().getCanonicalName())
                .setContent(CONTENT).build());
    }

    public InferenceEngine newEngine() {
        return newEngine(parser);
    }

    protected static void assertMessagesMatch(final Message actual, final Message expected) {
        Assert.assertEquals(expected, actual);
        final SimpleMessage actuals = (SimpleMessage) actual;
        final SimpleMessage expecteds = (SimpleMessage) expected;
        assertThat(actuals.getType(), is(equalTo(expecteds.getType())));
        assertThat(actuals.getContent(), is(equalTo(expecteds.getContent())));
    }
}
