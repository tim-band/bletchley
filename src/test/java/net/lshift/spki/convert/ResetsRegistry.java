package net.lshift.spki.convert;

import org.junit.Before;

public class ResetsRegistry {
    @Before
    public void resetRegistry() {
        Registry.resetRegistry();
    }
}
