package net.lshift.spki.schema;

import net.lshift.spki.convert.Convert;

@Convert.ByPosition(name="define", fields={"name", "value"})
public class Binding {
    public final String name;
    public final ConverterDeclaration value;

    public Binding(String name, ConverterDeclaration value) {
        this.name = name;
        this.value = value;
    }

}
