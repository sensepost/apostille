This is a tool to clone one or more X509 certificate (chain)s.

Provide it with a source KeyStore, and the appropriate passwords, and a
destination file, and Apostille will step through the entries in the 
KeyStore, and "replicate" them in the target KeyStore, complete with
matching PrivateKey's. Obviously, we are not breaking RSA/DSA/EC here,
so the PrivateKey will be freshly generated, along with it's PublicKey,
and an X509Certificate[] chain that matches the source chain in every 
respect except the key values.

Each item in the chain will result in an entry in the destination KeyStore,
each with the corresponding PrivateKey.

Automatically generated "parents" of the chain will be named by their CN.

Directly cloned items from the source KeyStore will be named by their alias.
