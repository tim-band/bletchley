package net.lshift.spki.convert;

@Convert.ByPosition(name="other-implementing-class", fields={})
public class OtherImplementingClass
    implements Interface
{
    public OtherImplementingClass()
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
