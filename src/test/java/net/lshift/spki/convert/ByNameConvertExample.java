package net.lshift.spki.convert;

import java.math.BigInteger;
import java.util.List;

@Convert.ByName("by-name-convert-example")
public class ByNameConvertExample {
    public final BigInteger foo;
    public final BigInteger bar;
    final String baz;
    public final List<String> inlineList;

    public ByNameConvertExample(BigInteger foo, BigInteger bar, String baz,
            List<String> inlineList) {
        this.foo = foo;
        this.bar = bar;
        this.baz = baz;
        this.inlineList = inlineList;
    }

    @Override
    public int hashCode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((bar == null) ? 0 : bar.hashCode());
        result = prime * result + ((baz == null) ? 0 : baz.hashCode());
        result = prime * result + ((foo == null) ? 0 : foo.hashCode());
        return result;
    }

    @Override
    public boolean equals(final Object obj)
    {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        final ByNameConvertExample other = (ByNameConvertExample) obj;
        if (bar == null) {
            if (other.bar != null) return false;
        } else if (!bar.equals(other.bar)) return false;
        if (baz == null) {
            if (other.baz != null) return false;
        } else if (!baz.equals(other.baz)) return false;
        if (foo == null) {
            if (other.foo != null) return false;
        } else if (!foo.equals(other.foo)) return false;
        return true;
    }

    @Override
    public String toString()
    {
        return "ConvertExample [bar=" + bar + ", baz=" + baz + ", foo=" + foo + "]";
    }
}

