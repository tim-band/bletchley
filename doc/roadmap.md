
The current version of Bletchley uses Canonical S-expressions on the wire, and
a schema language that is defined by a combination of Java types and annotations.

Bletchley requires developers to define their business domain using the schema language.

This means that if Bletchley is implemented in multiple programming languages,
those other programming languages need their own schema definition language,
and domain definitions need to be duplicated in each language.

On top of this, to define a security policy in Bletchley you need to start by
implementing conditions for your domain in Java, and then in any other languages
you want to support.

This also creates an impedence mismatch: you can't print out your security policy
except by printing out your coded conditions, so then you have to rely on
documentation.

We've chosen a solution to both these issues that's built around protocol
buffers, and CEL (common expression language). CEL defines expressions which
evaluate against protocol buffers, and conditions are then CEL expressions
that evaluate to a boolean value. 

We plan to:

 - Release a new version of Bletchley, implemented in Go, which uses
 protocol buffers as the basis of it's wire encoding. The basic structure 
 of messages, the concepts, and the cryptography is unchanged.
 - Release the Java version, and test interoperability
 - Add CEL support to the Go version
 
CEL is implemented only in Go, so this might not seem like much of a step
forward. We can't test interop with Java if we use CEL.

There are two ways forward:
 - Implement CEL in other languages
 - Figure out ways to use Bletchley as a service

What we expect to do is implement forward and reverse gRPC proxies. I.e.
the forward proxy makes Bletchley services look like gRPC services,
and the reverse proxy makes a gRPC service look like a Bletchley service.

This is actually fairly complicated, because the proxies have to
work out how to construct proofs and work out what encryption keys to
use automatically. This work will also make the library much easier
to use, however: we can just have Sender and Recipient objects.

