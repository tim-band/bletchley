package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.DictlikeSexp;

public class Point
{
    private final BigInteger x;
    private final BigInteger y;

    @DictlikeSexp("point")
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
