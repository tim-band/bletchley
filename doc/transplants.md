This is a list of changesets I either need to transplant
into bletchley from spki-suiteb, or failing that, there's a bug
or feature added in them that's needed in Bletchley.

b376411ecc97: applied | fixes enum converter

7f499e992a96: applied | fixes a quoting bug in the pretty printer

b3d1a12ef41d: applied | fixes an escaping bug in the reader

89d1c41d1273: applied | fixes the UUID parser so only canonical UUIDs are accepted

e257afe6c611: applied | adds converter support for booleans

e8550efb9a6e: applied | support for inline lists

    Did this with a separate commit, rather than a transplant

e10be4abb082: applied | Inferred inline lists

    This was stretching what was sensible as a transplant
