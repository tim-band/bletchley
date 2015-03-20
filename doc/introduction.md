
Cryptography
------------

Bletchley uses Ciphers as recommended by
[NSA Suite B](https://www.nsa.gov/ia/programs/suiteb_cryptography/) for
material rated TOP SECRET. There is no cipher negotiation.

We might decide to change the primitives used in future, but Bletchley won't
ever support cipher negotiation: versions of Bletchley which use different
cipher suites won't be compatible. In future you might be able to chose a
cipher suite for your application.

Architecture
------------

Bletchley can construct messages so that different systems see only the facets of 
the message required to do their job. It provides an API which exposes only data
which can be proven to be trustworthy to an application, which minimises the
risk of security bugs.

This faceted approach means that the signature on the original message can
be used for auditing, and this audit only trusts the source of the message, 
rather than any intermediate systems the message is processed by. This can be 
achieved simply by saving a journal of messages.

This contrasts with an SSL based approach, where systems only establish trust
in the systems they communicate with directly, and do not store an audit trail
that can be used to retrospectively verify that only trusted data was processed.
This is significant in the light of recent bugs found in SSL clients, and
because the configuration of the client: i.e. the trusted roots list can be
changed, possibly by an attacker.

In Java, Bletchley provides automatic conversion between annotated Java
objects and its wire encoding. Bletchley takes a ground up approach to this
which uses SPKI instead of more popular wire encodings like JSON and XML, 
because an important property of encoding for a cryptographic system is that it
is canonical. Systems which use XML and JSON must convert these into a canonical
format to create or verify a signature, and this vital code is complex. SPKI is 
designed so that the canonical form is trivial to generate. Canonical SPKI is 
also trivial to parse, which reduces the likelyhood of vulnerabilities in
network facing systems, particularly implementations in unsafe programming languages.

Documentation
-------------

[Manual](manual.md) (work in progress)


