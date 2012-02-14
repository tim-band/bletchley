package net.lshift.spki.convert;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;

import org.junit.Test;

public class PositionSequenceConverterTest extends ResetsRegistry {

    @Convert.PositionSequence(name="position-convert", fields={"first"}, seq="rest")
    public static class PositionSequenceExample {
        public final String first;
        public final List<String> rest;

        public PositionSequenceExample(String first, List<String> rest) {
            super();
            this.first = first;
            this.rest = rest;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((first == null) ? 0 : first.hashCode());
            result = prime * result + ((rest == null) ? 0 : rest.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null) return false;
            if (getClass() != obj.getClass()) return false;
            PositionSequenceExample other = (PositionSequenceExample) obj;
            if (first == null) {
                if (other.first != null) return false;
            } else if (!first.equals(other.first)) return false;
            if (rest == null) {
                if (other.rest != null) return false;
            } else if (!rest.equals(other.rest)) return false;
            return true;
        }
    }

    @Test
    public void canParse() throws IOException, InvalidInputException {
        PositionSequenceExample example = new PositionSequenceExample("this",
            Arrays.asList("that", "theother"));
        byte[] exampleBytes = s("(position-convert this that theother)");
        assertThat(
            ConvertUtils.toBytes(PositionSequenceExample.class, example),
            is(exampleBytes));
        assertThat(
            ConvertUtils.fromBytes(PositionSequenceExample.class, exampleBytes),
            is(example));
    }

    private byte[] s(String string) throws IOException, InvalidInputException {
        Sexp s = ConvertUtils.readAdvanced(Sexp.class,
            new ByteArrayInputStream(ConvertUtils.bytes(string)));
        return ConvertUtils.toBytes(Sexp.class, s);
    }

}
