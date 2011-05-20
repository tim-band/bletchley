package net.lshift.spki.convert;

public class ImplementingClass extends PositionBeanConvertible
    implements Interface
{
    @SExpName("implementing-class")
    public ImplementingClass()
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
