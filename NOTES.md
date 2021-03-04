# Tests

The test suite for this xar package is outdated.  In particular it expects
the old output format (sequence of integers), while newer crypto-lib
versions default to UTF-8 output format.

The following minimal XQuery test code was run from eXide. It verifies that
the library loads without errors, and runs simple AES encryption and MD5/SHA1
hash tests.

```
xquery version "3.1";

import module "http://expath.org/ns/crypto";

let $teststring := "Short string for tests."
(:let $expected-result :=:)
(:    <expected-result>222-157-20-54-132-99-46-30-73-43-253-148-61-155-86-141-51-56-40-42-31-168-189-56-236-102-58-237-175-171-9-87</expected-result>:)

let $encrypted := crypto:encrypt($teststring, "symmetric", "1234567890123456", "AES", (), "SunJCE")
let $decrypted := crypto:decrypt($encrypted, "symmetric", "1234567890123456", "AES", (), "SunJCE")

let $md5 := crypto:hash("Short string for tests.", "MD5", "UTF8")
let $sha1 := crypto:hash("Short string for tests.", "SHA-1", "base64")
return ($encrypted, $decrypted, $md5, $sha1)
```

Tests performed against fresh installations of eXist-db
* 4.7.1 (download from exist-db.org)
* 5.2.0 (download from exist-db.org)
* 5.3.0-SNAPSHOT (compiled from source)

With the default installation and no crypto-lib installed, tests obviously
fail on all versions.

With the default installation and crypto-lib 6.0.0RC1 installed, tests
succeed on all versions.

Fresh eXist 4.7.1 and crypto-lib 0.7 (last old version for exist < 5), tests
succeed.  Then upgrade to 6.0.0RC1 via packagemanger upload, upgrade works and
tests succeed.

Fresh eXist 5.2.0 and crypto-lib 1.0.0, tests fail on AES blocksize (this is
a known bug in 1.0.0).  Then upgrade to 5.3.0 via packagemanger from public
repo, upgrade works, tests fail with same error. Restart exist, tests succeed.
Then upgrade to 6.0.0RC1 via packagemanger upload, upgrade works and tests
succeed.

Fresh eXist 5.3.0-SNAPSHOT and crypto-lib 5.3.0 from public repo, tests fail
with duplicate function signature (known bug). Then upgrade to 6.0.0RC1 via
packagemanger upload, upgrade works, tests fail with same error. Restart
exist, tests succeed.

**Summary**

* 6.0.0RC1 seems to work on all tested eXist versions
* After upgrading crypto-lib via packagemanager, a restart of exist seemss mandatory
