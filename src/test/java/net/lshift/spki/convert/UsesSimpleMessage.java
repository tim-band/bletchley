package net.lshift.spki.convert;

import net.lshift.spki.Constants;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.simplemessage.SimpleMessage;

import org.junit.Before;

public class UsesSimpleMessage extends ResetsRegistry{
    private static final byte[] CONTENT = "The magic words are squeamish ossifrage".getBytes(Constants.ASCII);

    @Before
    @Override
    public void resetRegistry() {
        super.resetRegistry();
        Registry.getConverter(SimpleMessage.class);
    }

    protected Action makeMessage() {
        return new Action(new SimpleMessage(
            this.getClass().getCanonicalName(), CONTENT));
    }
}
