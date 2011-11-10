package net.lshift.spki.convert;

import net.lshift.spki.suiteb.simplemessage.SimpleMessage;

import org.junit.Before;

public class UsesSimpleMessage extends ResetsRegistry{
    @Before
    @Override
    public void resetRegistry() {
        super.resetRegistry();
        Registry.getConverter(SimpleMessage.class);
    }
}
