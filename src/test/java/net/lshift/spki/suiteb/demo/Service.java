package net.lshift.spki.suiteb.demo;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.SexpBacked;
import net.lshift.spki.suiteb.ActionType;

@Convert.ByName("suiteb-demo-service")
public class Service extends SexpBacked implements ActionType {
    public final String name;
    public final Integer port;

    public Service(final String name, final Integer port) {
        this.name = name;
        this.port = port;
    }
}
