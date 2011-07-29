package net.lshift.spki.convert;

import net.lshift.spki.suiteb.simplemessage.SimpleMessage;

import org.junit.Before;

public class ResetsRegistry {
    @Before
    public void resetRegistry() {
        Registry.resetRegistry();
        Registry.getConverter(SimpleMessage.class);
    }
}
