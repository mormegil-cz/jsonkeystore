jsonkeystore
============
Simple portable format for Java keystores.

Motivation
----------
Java keystores are usually based on opaque proprietary binary formats. What’s worse, the contents of a keystore might be non-portable, usable only with the same JRE as created it.

For instance, JCEKS keystores created with IBM Java (used e.g. on the IBM WebSphere application server) may be unreadable using the OpenJDK (or Oracle’s) Java, with attempts to use it ending with error messages like _Invalid secret key format_.

On the other hand, this library provides a simple JSON-based format for keystore representation which is portable among various JREs, OSes, and architectures.

It is not really intended to be used as the main keystore format, as it offers no key protection (no store or key password protection); it is meant mostly as a transport format for porting a keystore from one platform to another.

Let me say it once again: the format is insecure in that it provides no key protection; the keys are stored _unencrypted_. If you need protection, you need to ensure it on another layer, e.g. by encrypting the whole file during transport, etc.

Command-line tool usage
-----------------------
If you want to transfer a Java keystore file from one platform to another, you can first convert it on the source platform from the original format to the portable JSONKS format, transport the file to the target platform, and then convert it from the JSONKS format to the final target format.

For that use case, there is a simple keystore conversion tool available; it is similar to the `-importkeystore` option of the original Java `keytool` in that it allows conversion between any two formats supported by Java. The main advantage of this tool is that it the support of the JSONKS format is built-in.

Basic usage of the tool:

`java -jar keystoreconvert.jar -i INPUTFILE -o OUTPUTFILE -f INPUTFORMAT -t OUTPUTFORMAT`

The _INPUTFILE_ and _OUTPUTFILE_ are paths to the source and destination files; the _INPUTFORMAT_ and _OUTPUTFORMAT_ are names of the keystore formats known by Java (e.g. `JCEKS`, `JSONKS`).

If needed (it probably will be for most keystore formats), the store and key password can be specified using the `--keypass` and `--storepass` options.

Example to convert a JCEKS keystore to the JSONKS portable format:

`java -jar keystoreconvert.jar -i mykeystore.jceks -o converted.jsonks -f JCEKS -t JSONKS --keypass=changeit --storepass=changeit`

Example to convert a JSONKS format back to a JCEKS keystore:

`java -jar keystoreconvert.jar -i converted.jsonks -o restored.jceks -f JSONKS -t JCEKS --keypass=changeit --storepass=changeit`

Java library usage
------------------
The JSONKS format has been implemented as a standard Java Cryptography Architecture (JCA) provider, which means the keystore can be used everywhere where other keystore formats are used, if the format can be configured.

There are only two requirements:
- The keystore provider needs to be installed / configured correctly on the Java runtime.
- When creating a `java.security.KeyStore` instance, pass `JSONKS` as the type to the `KeyStore.getInstance()` call.

To make the JSONKS keystore format provider available to the Java runtime, you need to either enforce it directly in your code, by calling `JsonKeyStoreProvider.ensureRegistered()` (or by registering `Security.addProvider(new JsonKeyStoreProvider())` directly), which is a simple option useful mostly for testing or simple one-off tools.

If you want to make the JSONKS format available globally, you might want to install it to the JCA configuration on the machine. To do that, you need to modify the `java.security` configuration file on the machine: See e.g. [this document](https://docs.oracle.com/en/java/javase/11/security/howtoimplaprovider.html#JSSEC-GUID-831AA25F-F702-442D-A2E4-8DA6DEA16F33).

If you install the provider correctly, the following code should work correctly, just like for any other keystore format (the passwords are ignored for JSONKS):

```
final KeyStore ks = KeyStore.getInstance("JSONKS");
ks.load(inputStream, "");
final Key key = ks.getKey("test", "");
...
```

Author & license
----------------
The JSONKS format and its implementation is Copyright © 2020 Petr Kadlec. It is available under the MIT license.
