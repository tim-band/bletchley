package net.lshift.spki.suiteb.demo;

import net.lshift.spki.convert.Convert;

@Convert.ByName("suiteb-demo-service")
public class Service {
    public final String name;
    public final Integer port;

    public Service(String name, Integer port) {
        this.name = name;
        this.port = port;
    }
}
