package net.lshift.spki.convert;

import static net.lshift.spki.convert.UUIDConverter.validUUID;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.StringTokenizer;
import java.util.UUID;

import org.junit.Test;

public class UUIDConverterTest
{
    @Test
    public void testValidateCorrect() {
        assertTrue(validUUID(UUID.randomUUID().toString()));
    }

    @Test
    public void testValidateLongSegments() {
        testPartFormat("%012x");
        testPartFormat("%08x");
    }

    private static void testPartFormat(String partFormat) {
        StringBuffer buffer = new StringBuffer();
        StringTokenizer tokens = new StringTokenizer(UUID.randomUUID().toString(), "-");
        buffer.append(String.format(partFormat, Long.decode("0x" + tokens.nextToken())));
        buffer.append('-');
        buffer.append(String.format(partFormat, Long.decode("0x" + tokens.nextToken())));
        buffer.append('-');
        buffer.append(String.format(partFormat, Long.decode("0x" + tokens.nextToken())));
        buffer.append('-');
        buffer.append(String.format(partFormat, Long.decode("0x" + tokens.nextToken())));
        buffer.append('-');
        buffer.append(String.format(partFormat, Long.decode("0x" + tokens.nextToken())));
        // Just prove that UUID#fromString will accept the result
        UUID.fromString(buffer.toString());
        // And that we don't
        assertFalse(buffer.toString(), validUUID(buffer.toString()));
    }
}
