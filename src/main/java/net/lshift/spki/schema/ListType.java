package net.lshift.spki.schema;

import net.lshift.spki.convert.Convert;

@Convert.ByPosition(name="list-of", fields={"memberType"})
public class ListType implements Type{
    public final Type memberType;

    public ListType(Type memberType) {
        super();
        this.memberType = memberType;
    }
}
