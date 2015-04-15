package net.lshift.spki.schema;

import java.io.IOException;

import org.junit.Test;

import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.convert.UsesSimpleMessage;
import net.lshift.spki.suiteb.SequenceItem;

public class SchemaTest extends UsesSimpleMessage {
    @Test
    public void printSimpleMessageSchema() throws IOException {
        ConvertUtils.prettyPrint(Schema.schema(getReadInfo(), SequenceItem.class), System.out);
    }
}
