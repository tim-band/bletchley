package net.lshift.spki.schema;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.SexpBacked;

@Convert.ByPosition(name="option", fields={"name","type"})
public class Tagged extends SexpBacked {
    public final String name;
    public final Type type;

    public Tagged(String name, Type type) {
        super();
        this.name = name;
        this.type = type;
    }
}
