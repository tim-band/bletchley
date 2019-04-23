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
    extends UsesCatalog {
    enum TestEnum {
        LEFT,
        RIGHT
    }

    @Convert.ByPosition(name="enum-holder", fields="testEnum")
    public static class EnumHolder {
        public final TestEnum testEnum;

        public EnumHolder(final TestEnum testEnum) {
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
        final EnumHolder changeBack = ConvertUtils.fromBytes(getReadInfo(),
            EnumHolder.class, bytes);
        assertEquals(test.testEnum, changeBack.testEnum);
    }

    enum InvalidTestEnum {
        é
    }

    @Convert.ByPosition(name="invalid-enum-holder", fields="testEnum")
    public static class InvalidEnumHolder {
        public final InvalidTestEnum testEnum;

        public InvalidEnumHolder(final InvalidTestEnum testEnum) {
            this.testEnum = testEnum;
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void invalidEnumTest() throws InvalidInputException, IOException {
        ConvertUtils.toBytes(new InvalidEnumHolder(InvalidTestEnum.é));
    }
}
