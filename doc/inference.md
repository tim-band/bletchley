Quick Guide to the inference engine
===================================

The inference engine stands between a public facing service and your application code. It's responsibilities are to decrypt the parts of the message that can be decrypted, and to pass on only trusted parts of a message to the application layer. This is two responsibilities! In fact decryption and trust do not interact: The message could be decrypted in one pass and then evaluated in a second.

Representation
--------------
Messages are converted to Java objects before being processed by the inference engine. Some of these objects are understood by the inference engine and are called items, documented below. Action is an item type the user can extend with domain specific types. The inference engine doesn't process data inside these items, except to generate digests. These are conditionally passed on to the application, once processing is complete.

The items the inference engine does understand form an abstract syntax tree.

Conditions
----------
Trust is conditional. The only conditions Bletchley defines itself are
 * *Valid on or after*: trusted only ofter a certain date
 * *Invalid on or after*: not trusted after a certain date
 * *Untrusted*: I.e. uncoditionally untrusted. This is the start condition for the inference engine

You can combine conditions using logical and/or. This means you can use the two on or after conditions to make a key valid for a period of time, or just use the invalidate on after to revoke trust.

Condition is an extension point for Bletchley: users can implement there own conditions to add a permissions system, for example.

References
----------
Because of the canonical representation of all objects in a Bletchley schema, it's possible to repeatably generate a digest for any item in the message. This means items are content addressed using these digests. 

The inference engine keeps track of trust conditions for items and for public keys separate maps.

Processing
----------
Both trust and decryption are evaluated using forward chaining. I.e. items can only be processed if the required trust and/or keys have already been determined.

Messages are processed using recursive decent. Sub-trees are processed with a trust condition. Some item types calculate a new trust condition and process sub-items with it. Unless otherwise specified, sub-items are processed with the trust condition unchanged. The following are the item types understood by the inference engine:

 * *Action*: If the current trust conditions evaluate to true add the action to the list of accepted actions
 * *AES key*: An AES key, added to the set of known keys
 * *AES Packet*: An encrypted sub-tree. If the key is known, it will be decrypted and processed as a child of this item.
 * *Digest*: A digest. Assign the current trust condition to the item referred to by this digest
 * *ECDH*: If the private key of the recipient is known, and the public key of the sender is known, derive
           an EAS session key using ECDH, and add it to the list of known keys
 * *Limit*: process the subnodes with the current trust condition and the limit conditions.
 * *Passphrase protected key*: 
 * *Private Encryption Key*: Add the private encryption key to the pool of known keys
 * *Public Encryption Key*: Add the public key to the trust database with the current trust conditions
 * *Public Signing Key*: In trusted mode, add the key to the trusted set of keys
 * *Sequence*: process each child
 * *Signature*: Consists of a digest, a key id and the signature itself. If the public keys is known and the signture is valid, assign the trust condition of the public key to the item referred to by the digest.
 * *Signed*: Always contains a single sub-element, the payload. If there is known trust condition for the item, the sub elements are processed with that trust condition, otherwise process the content as untrusted.

