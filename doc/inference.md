=Quick Guide to the inference engine=

The inference engine stands between a public facing service and your application code. It's responsibility is decrypt the
parts of the message that can be decrypted, and to pass on only trusted parts of a message to the application layer.

It does this using forward chaining. I.e. nodes can only be processed if the required trust and/or keys have already been determined.

Messages are a tree. The following are the item types understood by the inference engine:

 * *Action*: To be passed on to the application layer
 * *AES key*: An AES key, added to the set of known keys
 * *AES Packet*: An encrypted subtree. If the key is known, it will be decrypted and processed
 * *Digest*: A digest. Add it to the list of things we trust
 * *ECDH*: If the private key of the recipient is known, and the public key of the sender is known, derive
           an EAS session key using ECDH, and add it to the list of known keys
 * *Limit*:
 * *Passphrase protected key*:
 * *Private Encryption Key*:
 * *Public Encryption Key*:
 * *Public Signing Key*:
 * *Sequence*:
 * *Signature*:
 * *Signed*:

It does this using forward chaining. That is, as it does a breadth first search of the message tree, it needs to have already
discovered the keys neccessary, 