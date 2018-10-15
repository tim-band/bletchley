package net.lshift.spki.schema;

import net.lshift.spki.convert.Convert;

@Convert.ByPosition(name="option", fields={"name","type"})
public class Tagged {
    public final String name;
    public final Type type;

    public Tagged(String name, Type type) {
        this.name = name;
        this.type = type;
    }
}
