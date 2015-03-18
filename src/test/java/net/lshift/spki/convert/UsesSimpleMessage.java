package net.lshift.spki.convert;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import net.lshift.spki.Constants;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.ActionType;
import net.lshift.spki.suiteb.simplemessage.SimpleMessage;

public class UsesSimpleMessage extends UsesCatalog {
    private static final byte[] CONTENT = "The magic words are squeamish ossifrage".getBytes(Constants.ASCII);
    private ConverterCatalog READ_INFO = super.getReadInfo().extend(SimpleMessage.class);

    @Override
    protected ConverterCatalog getReadInfo() {
        return READ_INFO;
    }

    protected Action makeMessage() {
        return new Action(new SimpleMessage(
            this.getClass().getCanonicalName(), CONTENT));
    }

    protected static void assertMessagesMatch(final ActionType actual, final ActionType expected) {
        final SimpleMessage actuals = (SimpleMessage) actual;
        final SimpleMessage expecteds = (SimpleMessage) expected;
        assertThat(actuals.type, is(equalTo(expecteds.type)));
        assertThat(actuals.content, is(equalTo(expecteds.content)));
    }
}
