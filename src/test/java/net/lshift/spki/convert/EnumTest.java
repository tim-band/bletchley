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
    extends ResetsRegistry {
    public static enum TestEnum {
        LEFT,
        RIGHT
    }

    @Test
    public void enumTest() throws InvalidInputException, IOException {
        final TestEnum test = TestEnum.LEFT;
        final byte[] bytes = ConvertUtils.toBytes(TestEnum.class, test);
        PrettyPrinter.prettyPrint(new PrintWriter(System.out),
            new ByteArrayInputStream(bytes));
        assertArrayEquals("4:left".getBytes("US-ASCII"), bytes);
        final TestEnum changeBack = ConvertUtils.fromBytes(
            TestEnum.class, bytes);
        assertEquals(test, changeBack);
    }
}
