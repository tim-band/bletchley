package net.lshift.spki.schema;

import net.lshift.spki.convert.Convert;

@Convert.ByPosition(name="feild", fields={"name","type"})
public class Field extends Tagged {

    public Field(String name, Type type) {
        super(name, type);
    }

}
