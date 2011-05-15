package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.NameBeanConvertable;
import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SExpName;

public class Point extends NameBeanConvertable
{
    private final BigInteger x;
    private final BigInteger y;

    @SExpName("point")
    public Point(
        @P("x") BigInteger x,
        @P("y") BigInteger y
    ) {
        super();
        this.x = x;
        this.y = y;
    }

    public BigInteger getX()
    {
        return x;
    }

    public BigInteger getY()
    {
        return y;
    }
}
