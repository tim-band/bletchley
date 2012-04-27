package net.lshift.spki.convert;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintWriter;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.PrettyPrinter;

import org.junit.Test;

public class EnumTest
    extends UsesConverting {
    public static enum TestEnum {
        LEFT,
        RIGHT
    }

    @Convert.ByPosition(name="enum-holder", fields="testEnum")
    public static class EnumHolder extends SexpBacked {
        public final TestEnum testEnum;

        public EnumHolder(final TestEnum testEnum) {
            super();
            this.testEnum = testEnum;
        }
    }

    @Test
    public void enumTest() throws InvalidInputException, IOException {
        final EnumHolder test = new EnumHolder(TestEnum.LEFT);
        final byte[] bytes = ConvertUtils.toBytes(test);
        PrettyPrinter.prettyPrint(new PrintWriter(System.out),
            new ByteArrayInputStream(bytes));
        assertArrayEquals("(11:enum-holder4:left)".getBytes("US-ASCII"), bytes);
        final EnumHolder changeBack = ConvertUtils.fromBytes(C,
            EnumHolder.class, bytes);
        assertEquals(test.testEnum, changeBack.testEnum);
    }
}
