package net.lshift.spki.convert;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.InferenceEngine;
import net.lshift.bletchley.suiteb.proto.SimpleMessageProto;
import net.lshift.bletchley.suiteb.proto.SimpleMessageProto.SimpleMessage;

import java.nio.charset.StandardCharsets;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;

public class UsesSimpleMessage extends UsesCatalog {
    private static final ByteString CONTENT = ByteString.copyFrom(
            "The magic words are squeamish ossifrage".getBytes(StandardCharsets.US_ASCII));

    protected Action makeMessage() {
        return new Action(
                Any.pack(SimpleMessageProto.SimpleMessage.newBuilder()
                .setType(this.getClass().getCanonicalName())
                .setContent(CONTENT).build()));
    }

    protected InferenceEngine<SimpleMessage> newEngine() {
        return newEngine(SimpleMessage.class);
    }

    protected static void assertMessagesMatch(final SimpleMessage actual, final SimpleMessage expected) {
        final SimpleMessage actuals = (SimpleMessage) actual;
        final SimpleMessage expecteds = (SimpleMessage) expected;
        assertThat(actuals.getType(), is(equalTo(expecteds.getType())));
        assertThat(actuals.getContent(), is(equalTo(expecteds.getContent())));
    }
}
