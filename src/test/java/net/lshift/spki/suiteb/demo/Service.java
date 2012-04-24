package net.lshift.spki.suiteb.demo;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.ActionType;

@Convert.ByName("suiteb-demo-service")
@Convert.InstanceOf(ActionType.class)
public class Service implements ActionType {
    public final String name;
    public final Integer port;

    public Service(final String name, final Integer port) {
        this.name = name;
        this.port = port;
    }
}
