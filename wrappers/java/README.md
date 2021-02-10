# BBS Signatures for Java

This is a Java wrapper for the C callable BBS+ Signatures package. The library depends on the native platform implementations of the BBS+ FFI wrapper. These are bundled with the package available on [Nuget](https://www.nuget.org/packages/Hyperledger.Ursa.BbsSignatures/).

# Build Rust Library

In order to build rust wrapper for the all available architectures, execute the following command:

```bash
./gradlew buildBinaries && ./gradlew copyBinaries
```

Gradle tasks will execute build scripts for rust compilation and then copy binaries to the specific jniLibs directories for Java wrapper to consume.

In situation when Rust wrapper methods were updated, update Java native methods to match the rust method signatures and generate new headers by running

```bash
cd ./wrappers/java/src/main/java/bbs/signatures
javac -h . Bbs.java BlindCommitmentContext.java BlindedKeyPair.java KeyPair.java ProofMessage.java
```

Compiler will create `bbs_signatures_bbs.h` with new JNI Methods matching Rust methods signature. 
For example, headers generated method

```java
Java_bbs_signatures_Bbs_bls_1public_1key_1g1_1size 
```

should match the Rust method 

```rust
pub extern "C" fn Java_bbs_signatures_Bbs_bls_1public_1key_1g1_1size(...)
```

# Unit testing

```bash
./gradlew test
```

# GPG Keys

Every java artifact must be signed with gpg key before publishing to repository
To generate a new key pair open a command prompt and run `gpg --gen-key`. It will guide you through the creation of your first keypair.

> Since GPG 2.1* the only fileformat supported by the Gradle Signing plugin is no longer used by default for GPG, to get around that we export the keypair we just created to the old format.

Next execute a following command to figure out the keyid for your keypair:

`gpg --list-key`

Example output:

```
gpg: checking the trustdb
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
gpg: next trustdb check due at 2019-06-17
C:/Users/phit/AppData/Roaming/gnupg/pubring.kbx
-----------------------------------------------
pub   rsa2048 2017-06-17 [SC] [expires: 2025-06-17]
      77273D57FA5140E5A91905087A1B92B81840D019
uid           [ultimate] bob@example.com
sub   rsa2048 2017-06-17 [E] [expires: 2025-06-17]
```

In this case we only have one key, `77273D57FA5140E5A91905087A1B92B81840D019` or short[*](https://security.stackexchange.com/questions/84280/short-openpgp-key-ids-are-insecure-how-to-configure-gnupg-to-use-long-key-ids-i/84281#84281) `1840D019` which is basically just the last 8 characters of the long ID.

Run this command to export a keyring in the format needed for gradle singning, replace the XXXXXXXX with your keyid. You will have to enter your passphrase for this.

`gpg --export-secret-key XXXXXXXX > ~/Desktop/keys.gpg`

This will create a file on your Desktop called `keys.gpg`, this is the file needed for Gradle signing process.

# Maven Central

In order to publish java ffi wrapper to maven central repository, need to specify the following environment variables inside `gradle.properties` file

```
signing.keyId=<key_id>
signing.password=<key_password>
signing.secretKeyRingFile=<path_to_private_key.gpg>
maven.username=<sonatype_username>
maven.password=<sonatype_password>
```

and execute 

```bash
./gradlew publish
```

New snapshot version must be specified in `build.gradle` 

```gradle
version '1.5-SNAPSHOT'
```

Published .jar snapshot will include the latest `jniLibs` which can be extracted by consumer

## Maven Local

For publishing to local maven repository for development purposes use 

```bash
./gradlew publishToMavenLocal --warning-mode all`
```

The resulting package will be available under

```bash
ls ~/.m2/repository/global/mattr/bbs.signatures

# To fix maven missing maven metadata error
cp ~/.m2/repository/global/mattr/bbs.signatures/maven-metadata-local.xml ~/.m2/repository/global/mattr/bbs.signatures/maven-metadata.xml
```