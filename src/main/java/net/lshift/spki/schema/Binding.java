package net.lshift.spki.schema;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.SexpBacked;

@Convert.ByPosition(name="define", fields={"name", "value"})
public class Binding extends SexpBacked {
    public final String name;
    public final ConverterDeclaration value;

    public Binding(String name, ConverterDeclaration value) {
        super();
        this.name = name;
        this.value = value;
    }

}
