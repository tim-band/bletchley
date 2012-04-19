package net.lshift.spki.suiteb.demo;

import java.io.IOException;

import net.lshift.spki.convert.Registry;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.convert.openable.OpenableUtils;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.SequenceItem;

public class WriteService {
    public static void writeService(Openable target, Service service)
                    throws IOException {
        Registry.getConverter(Service.class);
        OpenableUtils.write(SequenceItem.class,
            new Action(service), target);
    }
}
