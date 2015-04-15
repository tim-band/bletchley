package net.lshift.spki.schema;

import net.lshift.spki.convert.SexpBacked;
import net.lshift.spki.convert.Convert;

@Convert.ByPosition(name="vector", fields="componentType")
public class Vector 
extends SexpBacked 
implements ConverterDeclaration {
    public final Type componentType;

    public Vector(Type memberType) {
        super();
        this.componentType = memberType;
    }
}
