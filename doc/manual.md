
# Getting it


Bletchley is a java library.

Bletchley is built using [Maven 2](http://maven.apache.org), and a Maven
artifact is available from Central. Add it to your Maven project thus:


    <dependency>
      <groupId>net.lshift</groupId>
      <artifactId>bletchley</artifactId>
      <version>0.1</version>
    </dependency>


Here is an [example POM](https://github.com/lshift/bletchley-mail/blob/master/pom.xml)

# Concepts


Bletchley isn't just transport agnostic, it doesn't have any transports
or transport integrations. It produces and consumes messages, which are
streams of bytes. Because of this, you can store the messages if you want
to, or for that matter, use Bletchley to encrypt database fields.

A **message** contains some application data items and additional
data that establishes trust in this data. We call the
application data items **actions**, because the recipient acts on them.
Actions are Java classes defined by the application.

Because the message asks the recipient to act, It must determine if
the actions are trusted. At the core of Bletchley is a class that
takes a message, and returns only actions the recipient trusts.
This is called the **inference engine**. If you know about expert
systems, you can think about Bletchley as an expert system for trust.
If not, don't worry: it's not assumed knowledge.

An application creates an instance of the inference engine, and seeds
it with trust information. Bletchley is very flexible: You might have a single
**public signing key** that's trusted completely, or a number of
different keys which are trusted for specific actions, or for a specific
period of time. Each of these is called a **condition** and you can
create your own to match your problem domain.

On the wire, Bletchley encodes data using a binary encoding of s-expressions
very similar to the one used in SPKI. Bletchley converts between Java
objects and s-expressions using the **converter** nominated by the class. Conversion to
Java classes requires a **converter catalog**, to help it find relevant classes
during conversion. This isn't needed for serialization since the converter for
a class is specified by annotations on that class. The converter catalog
generally needs to contain an entry for each action class and each custom
condition class.

# API

This introduction to the API is a bit of a script, in that it suggests an
order of development that should prove productive.

## Define an Action


As covered above, Bletchley applications pass actions to each other, so
the first thing to do is define an action class.

Let's say we are writing a home automation system. Our first action
controls a switch:

    package homeautomation;

    import net.lshift.spki.convert.Convert;
    import net.lshift.spki.suiteb.ActionType;

    @Convert.ByPosition(fields = { "name", "on" }, name = "set-switch")
    public class SetSwitch implements ActionType {
        public final String name;
        public final boolean on;

        public SetSwitch(String name, boolean on) {
            this.name = name;
            this.on = on;
        }
    }

Briefly: We annotate the class to tell Bletchley how it's converted.
ByPosition means assign a position to each field. This is the most
compact and straightforward representation. The other alternative
is @Convert.ByName which labels each field. We will cover the differences
in more detail in the conversion section.

The above applies to all the classes we want to use in messages, so
if action refers to other classes, you must also annotate those.

Actions need to implement ActionType.

This class follows a convention of immutable message types. This
isn't a requirement of the library, it's just good practice.

We need a converter catalog:

    package homeautomation;

    import net.lshift.spki.convert.ConverterCatalog;

    public class Actions {
        public static final ConverterCatalog CATALOG = ConverterCatalog.BASE.extend(SetSwitch.class);
    }


extend is a varargs method, so you can list as many classes as you
like. Add each additional action this way, and any classes it refers
to will also be added to the catalog automatically.

Write some tests to prove that conversion is set up correctly:


    package homeautomation;

    import net.lshift.spki.InvalidInputException;
    import net.lshift.spki.convert.ConvertUtils;

    import org.junit.Test;

    public class SetSwitchTest {
        @Test
        public void testConvert() throws InvalidInputException {
            ConvertUtils.fromBytes(
                Actions.CATALOG,
                SetSwitch.class,
                ConvertUtils.toBytes(new SetSwitch("bathroom-light", true)));
        }
    }


And now you know how to convert to and from byte arrays as well...

## Signing

For now, lets assume that the fact you are turning the light on
or off isn't a secret. We just don't want pranksters turning the
lights on and off.

We are going to build up our example using unit tests. Ultimately,
you will need to load keys from files, but for now, we will just
generate keys in our test set-up.

Our public key system works as follows: Our switches will trust
a single key. Our controllers will each have their own key,
signed by the root key for a limited time.

TO BE CONTINUED...
