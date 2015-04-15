package net.lshift.spki.schema;

import net.lshift.spki.convert.Convert;

@Convert.ByPosition(name="option", fields={"name","type"})
public class Option extends Tagged {

    public Option(String name, Type type) {
        super(name, type);
    }

}
