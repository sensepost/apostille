This is a tool to clone one or more X509 certificate (chain)s.

Call it with a host:port that will present an SSL certificate chain, and
Apostille will retrieve the chain, and output a key, and a chain of 
certificates that matches the certs that were retrieved. 

Obviously, we are not breaking RSA/DSA/EC here, so the PrivateKey will be 
freshly generated, along with its PublicKey, and an X509Certificate[] 
chain that matches the source chain in every respect EXCEPT the key values.

If you provide a keystore and passwords, all private keys and certificates 
generated will be stored in the keystore, as well as being output in PEM 
form on stdout. This will include the keys for all the intermediate 
certificates, which would not otherwise be saved.

Automatically generated "parents" of the chain will be named by their CN.

Run it like:

	mvn package
	java -jar target/apostille-1.0-SNAPSHOT.jar example.com:443 dstkeystore.jks kspassword keypassword > example.com.key+chain

Provide it with a source KeyStore, and the appropriate passwords, and a
destination file, and Apostille will step through the entries in the 
KeyStore, and "replicate" them in the target KeyStore, complete with
matching PrivateKey's. Obviously, we are not breaking RSA/DSA/EC here,
so the PrivateKey will be freshly generated, along with it's PublicKey,
and an X509Certificate[] chain that matches the source chain in every 
respect except the key values. The utility of this mode is perhaps not
immediately obvious, but it was useful to me at the time! :-)

Directly cloned items from the source KeyStore will be named by their alias.

Run it like:

	java -jar target/apostille-1.0-SNAPSHOT.jar srckeystore.jks dstkeystore.jks kspassword keypassword

