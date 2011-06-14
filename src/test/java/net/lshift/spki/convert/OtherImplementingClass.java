package net.lshift.spki.convert;

@Convert.ByPosition
public class OtherImplementingClass
    implements Interface
{
    @SexpName("other-implementing-class")
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
    public boolean equals(Object obj)
    {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        return true;
    }
}
