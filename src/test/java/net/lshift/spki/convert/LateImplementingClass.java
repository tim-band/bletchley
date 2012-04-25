package net.lshift.spki.convert;

@Convert.ByPosition(name="late-implementing-class", fields={})
@Convert.InstanceOf(Interface.class)
public class LateImplementingClass
    extends SexpBacked
    implements Interface
{
    public LateImplementingClass()
    {
        super();
    }

    @Override
    public int hashCode()
    {
        return 1;
    }

    @Override
    public boolean equals(final Object obj)
    {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        return true;
    }
}
