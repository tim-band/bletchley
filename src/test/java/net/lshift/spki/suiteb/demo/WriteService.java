package net.lshift.spki.suiteb.demo;

import java.io.IOException;

import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.convert.openable.OpenableUtils;

public class WriteService {
    public static void writeService(Openable target, Service service)
                    throws IOException {
        OpenableUtils.write(Service.class, service, target);
    }
}
