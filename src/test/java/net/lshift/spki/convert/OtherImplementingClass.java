package net.lshift.spki.convert;

public class OtherImplementingClass extends PositionBeanConvertible
    implements Interface
{
    @SExpName("other-implementing-class")
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
