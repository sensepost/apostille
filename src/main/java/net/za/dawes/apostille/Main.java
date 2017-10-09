package net.za.dawes.apostille;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;
import java.util.Enumeration;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Main {

	public static X509KeyManager cloneCertificates(KeyStore ks, String alias, X509Certificate[] certs,
			char[] keyPassword) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException,
			CertificateException {
		if (certs == null || certs.length == 0)
			throw new NullPointerException("Certs[] cannot be null or zero-length!");

		PrivateKey caKey = null;

		X509Certificate[] myCerts = new X509Certificate[certs.length];
		try {
			KeyPair keyPair = null;
			Certificate[] chain = null;
			for (int i = certs.length - 1; i >= 0; i--) {
				// generate a key pair that matches the parameters of the
				// certificates public key
				keyPair = generateKeyPair(certs[i].getPublicKey());

				Date startDate = certs[i].getNotBefore();
				Date expiryDate = certs[i].getNotAfter();
				BigInteger serialNumber = certs[i].getSerialNumber();
				X500Principal subject = certs[i].getSubjectX500Principal();
				X500Principal issuer = certs[i].getIssuerX500Principal();

				if (caKey == null) {
					if (!issuer.equals(subject)) {
						try {
							String caCN = getCN(issuer);
							// Do we already have a private key for the issuer?
							caKey = (PrivateKey) ks.getKey(caCN, keyPassword);
							if (caKey == null) {
								// Can we find the issuer details in the local
								// trust store?
								X509Certificate caCert = getCaCertificate(caCN);
								if (caCert != null) {
									// found issuer details, create a new cert
									// for the issuer and add it to the keystore
									X509KeyManager caKm = cloneCertificates(ks, null, new X509Certificate[] { caCert },
											keyPassword);
									caKey = caKm.getPrivateKey(caCN);
								}
							}
							if (caKey == null) {
								// We can't find the right details, let's make
								// this a self-signed cert instead of failing
								System.err.println("WARNING: Cannot find certificate details for '" + issuer
										+ "', self-signing using '" + subject + "'");
								issuer = subject;
								caKey = keyPair.getPrivate();
							}
						} catch (UnrecoverableKeyException e) {
							throw new CertificateException(e);
						}
					} else {
						caKey = keyPair.getPrivate();
					}
				}

				X509v3CertificateBuilder generator = new JcaX509v3CertificateBuilder(issuer, serialNumber, startDate,
						expiryDate, subject, keyPair.getPublic());

				Set<String> criticalExtensionOids = certs[i].getCriticalExtensionOIDs();
				for (String oid : criticalExtensionOids) {
					byte[] ext = certs[i].getExtensionValue(oid);
					ASN1Primitive p = getObject(oid, ext);
					generator.addExtension(new ASN1ObjectIdentifier(oid), true, p);
				}
				Set<String> nonCriticalExtensionOids = certs[i].getNonCriticalExtensionOIDs();
				for (String oid : nonCriticalExtensionOids) {
					byte[] ext = certs[i].getExtensionValue(oid);
					ASN1Primitive p = getObject(oid, ext);
					generator.addExtension(new ASN1ObjectIdentifier(oid), false, p);
				}

				X509Certificate cert;
				try {
					cert = signCertificate(generator, caKey, certs[i].getSigAlgName());
				} catch (OperatorCreationException e) {
					throw new CertificateException(e);
				}
				caKey = keyPair.getPrivate();

				myCerts[i] = cert;

				chain = new Certificate[certs.length - i];
				System.arraycopy(myCerts, i, chain, 0, chain.length);

				String cn = getCN(cert.getSubjectX500Principal());
				ks.setKeyEntry(alias != null ? alias : cn, keyPair.getPrivate(), keyPassword, chain);
			}
			if (chain != null)
				return new SingleX509KeyManager(alias, keyPair.getPrivate(), chain);
		} catch (RuntimeException | AnnotatedException | CertIOException e) {
			throw new CertificateException(e);
		}
		throw new RuntimeException("Should not be able to get here!");
	}

	private static X509Certificate getCaCertificate(String cn) throws NoSuchAlgorithmException, KeyStoreException {
		TrustManagerFactory trustManagerFactory = TrustManagerFactory
				.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init((KeyStore) null);
		TrustManager[] tms = trustManagerFactory.getTrustManagers();
		for (TrustManager tm : tms) {
			X509Certificate[] certs = ((X509TrustManager) tm).getAcceptedIssuers();
			for (X509Certificate cert : certs) {
				if (cn.equals(getCN(cert.getSubjectX500Principal()))) {
					return cert;
				}
			}
		}
		return null;
	}

	private static String getCN(X500Principal principal) {
		X500Name x500Name = new X500Name(principal.getName());
		RDN cn = x500Name.getRDNs()[0];
		return IETFUtils.valueToString(cn.getFirst().getValue());
	}

	private static KeyPair generateKeyPair(PublicKey pubKey)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		String keyAlg = pubKey.getAlgorithm();
		AlgorithmParameterSpec params = null;
		if ("RSA".equals(keyAlg)) {
			RSAPublicKey rsaKey = (RSAPublicKey) pubKey;
			params = new RSAKeyGenParameterSpec(rsaKey.getModulus().bitLength(), rsaKey.getPublicExponent());
		} else if ("EC".equals(keyAlg)) {
			ECPublicKey ecKey = (ECPublicKey) pubKey;
			params = ecKey.getParams();
		} else if ("DSA".equals(keyAlg)) {
			DSAPublicKey dsaKey = (DSAPublicKey) pubKey;
			DSAParams p = dsaKey.getParams();
			params = new DSAParameterSpec(p.getP(), p.getQ(), p.getG());
		} else {
			throw new UnsupportedOperationException("No support for " + keyAlg);
		}

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlg);
		keyGen.initialize(params);
		return keyGen.generateKeyPair();
	}

	public static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;

	private static X509Certificate signCertificate(X509v3CertificateBuilder certificateBuilder, PrivateKey privateKey,
			String signatureAlgorithm) throws CertificateException, OperatorCreationException {
		ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).build(privateKey);
		X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signer));
		return cert;
	}

	private static ASN1Primitive getObject(String oid, byte[] ext) throws AnnotatedException {
		try {
			ASN1InputStream aIn = new ASN1InputStream(ext);
			ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
			aIn.close();

			aIn = new ASN1InputStream(octs.getOctets());
			ASN1Primitive p = aIn.readObject();
			aIn.close();
			return p;
		} catch (Exception e) {
			throw new AnnotatedException("exception processing extension " + oid, e);
		}
	}

	public static X509Certificate certFromDer(byte[] der) throws CertificateException {
		InputStream is = new ByteArrayInputStream(der);
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) certFactory.generateCertificate(is);
		return cert;
	}

	public static X509Certificate[] certsFromServer(String host, int port)
			throws IOException, UnknownHostException, NoSuchAlgorithmException, KeyManagementException {
		SSLContext sslContext = SSLContext.getInstance("TLS");
		LoggingTrustManager tm = new LoggingTrustManager();
		sslContext.init(null, new TrustManager[] { tm }, null);

		SSLSocketFactory factory = sslContext.getSocketFactory();
		SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
		try {
			socket.startHandshake();
		} catch (Exception e) {

		} finally {
			socket.close();
		}
		if (tm.certs == null)
			throw new RuntimeException("Couldn't get the certs");
		return tm.certs;
	}

	private static class LoggingTrustManager implements X509TrustManager {

		X509Certificate[] certs;

		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		}

		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			certs = new X509Certificate[chain.length];
			System.arraycopy(chain, 0, certs, 0, chain.length);
		}

		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}
	};

	private static X509Certificate[] copy(Certificate[] certs) {
		if (certs == null)
			return null;
		X509Certificate[] copy = new X509Certificate[certs.length];
		System.arraycopy(certs, 0, copy, 0, certs.length);
		return copy;
	}

	private static void outputKeyAndCertificate(String alias, X509KeyManager km, Writer out) throws IOException {
		JcaPEMWriter w = new JcaPEMWriter(out);
		out.write("Key for " + alias + "\n");
		w.writeObject(km.getPrivateKey(alias));
		w.flush();
		X509Certificate[] certs = km.getCertificateChain(alias);
		for (int i = certs.length - 1; i >= 0; i--) {
			out.write("Certificate " + i + ": Subject = " + certs[i].getSubjectX500Principal() + "\n");
			out.write("Certificate " + i + ": Issuer  = " + certs[i].getIssuerX500Principal() + "\n");
			w.writeObject(certs[i]);
			w.flush();
		}
		w.close();
	}

	private static class SingleX509KeyManager extends X509ExtendedKeyManager {

		private String alias;

		private PrivateKey pk;

		private X509Certificate[] certs;

		public SingleX509KeyManager(String alias, PrivateKey pk, Certificate[] certs) {
			this.alias = alias;
			this.pk = pk;
			this.certs = copy(certs);
		}

		public SingleX509KeyManager(KeyStore ks, char[] password, String alias)
				throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
			this.alias = alias;
			this.pk = (PrivateKey) ks.getKey(alias, password);
			this.certs = copy(ks.getCertificateChain(alias));
		}

		@Override
		public String chooseEngineClientAlias(String[] paramArrayOfString, Principal[] paramArrayOfPrincipal,
				SSLEngine paramSSLEngine) {
			return alias;
		}

		@Override
		public String chooseEngineServerAlias(String paramString, Principal[] paramArrayOfPrincipal,
				SSLEngine paramSSLEngine) {
			return alias;
		}

		public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
			return alias;
		}

		public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
			return alias;
		}

		public X509Certificate[] getCertificateChain(String alias) {
			return copy(certs);
		}

		public String[] getClientAliases(String keyType, Principal[] issuers) {
			return new String[] { alias };
		}

		public PrivateKey getPrivateKey(String alias) {
			return pk;
		}

		public String[] getServerAliases(String keyType, Principal[] issuers) {
			return new String[] { alias };
		}

		private X509Certificate[] copy(Certificate[] certs) {
			if (certs == null)
				return null;
			X509Certificate[] copy = new X509Certificate[certs.length];
			System.arraycopy(certs, 0, copy, 0, certs.length);
			return copy;
		}

	}

	public static void main(String[] args) throws Exception {
		if (args.length != 1 && args.length != 4) {
			System.out.println("Usage: java -jar apostille.jar host:443");
			System.out.println("Usage: java -jar apostille.jar src.jks dst.jks <keystore_password> <key_password>");
			System.exit(0);
		}
		File src = new File(args[0]);
		File dst = args.length > 1 ? new File(args[1]) : null;
		char[] ksp = (args.length > 2 ? args[2] : "password").toCharArray();
		char[] kp = (args.length > 3 ? args[3] : "password").toCharArray();
		KeyStore srcKs = KeyStore.getInstance(KeyStore.getDefaultType());
		KeyStore dstKs = KeyStore.getInstance(KeyStore.getDefaultType());
		if (dst != null && dst.exists()) {
			dstKs.load(new FileInputStream(dst), ksp);
			Enumeration<String> aliases = dstKs.aliases();
			System.err.println("Provided keystore has the following aliases:");
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				System.err.println("Alias: " + alias);
			}
		} else {
			dstKs.load(null, ksp);
		}

		try (Writer w = new OutputStreamWriter(System.out)) {
			if (!src.exists()) {
				int c = args[0].indexOf(':');
				if (c > 0) {
					srcKs.load(null, ksp);

					String host = args[0].substring(0, c);
					int port = Integer.parseInt(args[0].substring(c + 1));

					X509Certificate[] certs = certsFromServer(host, port);
					String alias = getCN(certs[0].getSubjectX500Principal());
					X509KeyManager km = cloneCertificates(dstKs, alias, certs, kp);

					outputKeyAndCertificate(alias, km, w);
				} else {
					System.err.println("Keystore " + src + " not found, and it doesn't look like a host:port");
				}
			} else {
				srcKs.load(new FileInputStream(src), ksp);
				Enumeration<String> aliases = srcKs.aliases();
				while (aliases.hasMoreElements()) {
					String alias = aliases.nextElement();
					System.err.println("Copying " + alias);
					X509Certificate[] certs = copy(srcKs.getCertificateChain(alias));
					if (certs == null) {
						Certificate cert = srcKs.getCertificate(alias);
						if (cert != null) {
							certs = new X509Certificate[] { (X509Certificate) cert };
						} else {
							throw new KeyStoreException("Can't get certificate chain for '" + alias + "'");
						}
					}
					X509KeyManager km = cloneCertificates(dstKs, alias, certs, kp);
					outputKeyAndCertificate(alias, km, w);
				}
			}
		}

		Enumeration<String> aliases = dstKs.aliases();
		if (dst != null && aliases.hasMoreElements()) {
			dstKs.store(new FileOutputStream(dst), ksp);
			System.err.println("Provided keystore now has the following aliases:");
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				System.err.println("Alias: " + alias + ", added " + dstKs.getCreationDate(alias));
			}

		}
	}
}
