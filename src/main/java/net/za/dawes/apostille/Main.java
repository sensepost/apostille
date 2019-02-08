package net.za.dawes.apostille;

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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
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
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Main {

	private KeyStore keystore;
	private char[] keyPass;

	private Main(KeyStore keystore, char[] keyPass) {
		if (keystore == null)
			throw new NullPointerException("keystore");
		this.keystore = keystore;
		this.keyPass = keyPass;
	}

	private X509KeyManager cloneCertificates(String alias,
			List<X509Certificate> certs) throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, KeyStoreException,
			CertificateException, UnrecoverableKeyException {
		if (certs == null || certs.size() == 0)
			throw new NullPointerException(
					"Certs cannot be null or zero-length!");

		if (keystore.containsAlias(alias) && keystore.isKeyEntry(alias))
			return new SingleX509KeyManager(alias, keystore, keyPass);

		X509Certificate cert = certs.get(0);

		X500Principal subject = cert.getSubjectX500Principal();
		X500Principal issuer = cert.getIssuerX500Principal();

		X509KeyManager caKm = null;

		if (!issuer.equals(subject)) {
			String caDN = getDN(issuer);
			if (certs.size() > 1) {
				caKm = cloneCertificates(caDN, certs.subList(1, certs.size()));
			} else {
				caKm = getCAKeyManager(caDN);
			}
			if (caKm == null) {
				System.err
						.println("WARNING: Cannot find certificate details for '"
								+ caDN
								+ ", will self-sign instead.\n"
								+ "If this is not what you want, find the CA certificate for '"
								+ caDN
								+ "', and add it to the keystore passed as a parameter on the command line");
				// FIXME: Figure out a way to construct a fake
				// CA certificate here, based on the issuer name
				// and other details in the certificate
			}
		}

		// generate a key pair that matches the parameters of the
		// certificates public key
		KeyPair keyPair = generateKeyPair(cert.getPublicKey());

		X509KeyManager km = copyAndSign(cert, keyPair, caKm);
		keystore.setKeyEntry(alias, keyPair.getPrivate(), keyPass,
				km.getCertificateChain(alias));
		return km;
	}

	private X509KeyManager copyAndSign(X509Certificate cert, KeyPair keyPair,
			X509KeyManager caKm) throws CertificateException {
		try {
			Date startDate = cert.getNotBefore();
			Date expiryDate = cert.getNotAfter();
			BigInteger serialNumber = cert.getSerialNumber();
			X500Principal subject = cert.getSubjectX500Principal();
			X500Principal issuer = caKm == null ? subject : cert
					.getIssuerX500Principal();

			X509v3CertificateBuilder generator = new JcaX509v3CertificateBuilder(
					issuer, serialNumber, startDate, expiryDate, subject,
					keyPair.getPublic());

			Set<Extension> extensions = getExtensions(cert);
			for (Extension extension : extensions) {
				generator.addExtension(extension);
			}
			
			Certificate[] caChain = caKm == null ? new Certificate[0] : caKm
					.getCertificateChain(null);
			Certificate[] chain = new Certificate[caChain.length + 1];
			System.arraycopy(caChain, 0, chain, 1, caChain.length);

			PrivateKey caKey = caKm == null ? keyPair.getPrivate() : caKm
					.getPrivateKey(null);

			chain[0] = signCertificate(generator, caKey, cert.getSigAlgName());

			String alias = getDN(subject);

			return new SingleX509KeyManager(alias, keyPair.getPrivate(), chain);
		} catch (Exception e) {
			throw new CertificateException(e);
		}
	}

	private Set<Extension> getExtensions(X509Certificate cert) {
		Set<Extension> extensions = new LinkedHashSet<>();
		Set<String> criticalExtensionOids = cert.getCriticalExtensionOIDs();
		for (String oid : criticalExtensionOids) {
			byte[] ext = cert.getExtensionValue(oid);
			extensions.add(new Extension(new ASN1ObjectIdentifier(oid), true, ext));
		}
		Set<String> nonCriticalExtensionOids = cert
				.getNonCriticalExtensionOIDs();
		for (String oid : nonCriticalExtensionOids) {
			byte[] ext = cert.getExtensionValue(oid);
			extensions.add(new Extension(new ASN1ObjectIdentifier(oid), false, ext));
		}
		return extensions;
	}

	private X509KeyManager getCAKeyManager(String caCN)
			throws CertificateException {
		// is the certificate already in the keystore?
		try {
			if (keystore.containsAlias(caCN) && keystore.isKeyEntry(caCN)) {
				return new SingleX509KeyManager(caCN, keystore, keyPass);
			} else {
				List<X509Certificate> caCert = getCaCertificate(keystore, caCN);
				if (caCert != null) {
					return cloneCertificates(caCN, caCert);
				}
				caCert = getCaCertificate(null, caCN);
				if (caCert != null) {
					return cloneCertificates(caCN, caCert);
				}
				return null;
			}
		} catch (UnrecoverableKeyException | KeyStoreException
				| NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new CertificateException(e);
		}
	}

	private List<X509Certificate> getCaCertificate(KeyStore keystore, String dn)
			throws NoSuchAlgorithmException, KeyStoreException {
		TrustManagerFactory trustManagerFactory = TrustManagerFactory
				.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init(keystore);
		TrustManager[] tms = trustManagerFactory.getTrustManagers();
		for (TrustManager tm : tms) {
			X509Certificate[] certs = ((X509TrustManager) tm)
					.getAcceptedIssuers();
			for (X509Certificate cert : certs) {
				if (dn.equals(getDN(cert.getSubjectX500Principal()))) {
					return Arrays.asList(new X509Certificate[] { cert });
				}
			}
		}
		return null;
	}

	private static String getDN(X500Principal principal) {
		return principal.getName(X500Principal.RFC1779);
	}

	private static KeyPair generateKeyPair(PublicKey pubKey)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		String keyAlg = pubKey.getAlgorithm();
		AlgorithmParameterSpec params = null;
		if ("RSA".equals(keyAlg)) {
			RSAPublicKey rsaKey = (RSAPublicKey) pubKey;
			params = new RSAKeyGenParameterSpec(
					rsaKey.getModulus().bitLength(), rsaKey.getPublicExponent());
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

	private X509Certificate signCertificate(
			X509v3CertificateBuilder certificateBuilder, PrivateKey privateKey,
			String signatureAlgorithm) throws CertificateException,
			OperatorCreationException {
		ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
				.build(privateKey);
		return new JcaX509CertificateConverter()
				.getCertificate(certificateBuilder.build(signer));
	}

	private static ASN1Primitive getObject(String oid, byte[] ext)
			throws AnnotatedException {
		try {
			ASN1InputStream aIn = new ASN1InputStream(ext);
			ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
			aIn.close();

			aIn = new ASN1InputStream(octs.getOctets());
			ASN1Primitive p = aIn.readObject();
			aIn.close();
			return p;
		} catch (Exception e) {
			throw new AnnotatedException("exception processing extension "
					+ oid, e);
		}
	}

	private static List<X509Certificate> certsFromServer(String host, int port)
			throws IOException, UnknownHostException, NoSuchAlgorithmException,
			KeyManagementException {
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
		return Arrays.asList(tm.certs);
	}

	private static List<X509Certificate> certsFromStream(InputStream in)
			throws IOException, CertificateException {
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		Collection<? extends Certificate> certs = fact.generateCertificates(in);
		List<X509Certificate> ret = new ArrayList<>();
		Iterator<? extends Certificate> it = certs.iterator();
		while (it.hasNext()) {
			Certificate cert = it.next();
			if (cert instanceof X509Certificate) {
				X509Certificate xcert = (X509Certificate) cert;
				System.err.println(xcert.getSubjectX500Principal() + " issued "
						+ xcert.getNotBefore());
				ret.add((X509Certificate) cert);
			}
		}

		return ret;
	}

	private static class LoggingTrustManager implements X509TrustManager {

		X509Certificate[] certs;

		public void checkClientTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
		}

		public void checkServerTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
			certs = new X509Certificate[chain.length];
			System.arraycopy(chain, 0, certs, 0, chain.length);
		}

		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}
	};

	private static void outputKeyAndCertificate(String alias,
			X509KeyManager km, Writer out) throws IOException {
		JcaPEMWriter w = new JcaPEMWriter(out);
		out.write("Key for " + alias + "\n");
		w.writeObject(km.getPrivateKey(alias));
		w.flush();
		X509Certificate[] certs = km.getCertificateChain(alias);
		for (int i = certs.length - 1; i >= 0; i--) {
			out.write("Certificate " + i + ": Subject = "
					+ certs[i].getSubjectX500Principal() + "\n");
			out.write("Certificate " + i + ": Issuer  = "
					+ certs[i].getIssuerX500Principal() + "\n");
			w.writeObject(certs[i]);
			w.flush();
		}
	}

	private static class SingleX509KeyManager extends X509ExtendedKeyManager {

		private String alias;

		private PrivateKey pk;

		private X509Certificate[] certs;

		public SingleX509KeyManager(String alias, PrivateKey pk,
				Certificate[] certs) {
			this.alias = alias;
			this.pk = pk;
			this.certs = copy(certs);
		}

		public SingleX509KeyManager(String alias, KeyStore keystore,
				char[] keyPass) throws UnrecoverableKeyException,
				KeyStoreException, NoSuchAlgorithmException {
			this.alias = alias;
			this.pk = (PrivateKey) keystore.getKey(alias, keyPass);
			this.certs = copy(keystore.getCertificateChain(alias));
		}

		@Override
		public String chooseEngineClientAlias(String[] paramArrayOfString,
				Principal[] paramArrayOfPrincipal, SSLEngine paramSSLEngine) {
			return alias;
		}

		@Override
		public String chooseEngineServerAlias(String paramString,
				Principal[] paramArrayOfPrincipal, SSLEngine paramSSLEngine) {
			return alias;
		}

		public String chooseClientAlias(String[] keyType, Principal[] issuers,
				Socket socket) {
			return alias;
		}

		public String chooseServerAlias(String keyType, Principal[] issuers,
				Socket socket) {
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
		if (args.length < 1 || args.length > 4) {
			System.out
					.println("Usage: java -jar apostille.jar <src> [dst.jks [<keystore_password> [<key_password>]]]");
			System.out.println();
			System.out
					.println("\tWhere <src> can be a file containing a certificate chain in PEM format");
			System.out
					.println("\tor a hostname:port to connect to, to obtain the certificate chain");
			System.out.println();
			System.out
					.println("You can optionally provide a keystore to save intermediate private keys into");
			System.out
					.println("which can be used on a later run with a different certificate to maintain a");
			System.out.println("consistent certificate hierarchy.");
			System.out
					.println("If the keystore password or key password are not provided, they will default to 'password'");
			System.exit(0);
		}
		File src = new File(args[0]);
		File dst = args.length > 1 ? new File(args[1]) : null;
		char[] ksp = (args.length > 2 ? args[2] : "password").toCharArray();
		char[] kp = (args.length > 3 ? args[3] : "password").toCharArray();
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		if (dst != null && dst.exists()) {
			keystore.load(new FileInputStream(dst), ksp);
			Enumeration<String> aliases = keystore.aliases();
			System.err
					.println("Provided destination keystore already has the following aliases:");
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				System.err.println("Alias: " + alias);
			}
		} else {
			keystore.load(null, ksp);
		}

		Main main = new Main(keystore, kp);

		try (Writer out = new OutputStreamWriter(System.out)) {
			if (!src.exists()) {
				int c = args[0].indexOf(':');
				if (c > 0) {
					String host = args[0].substring(0, c);
					int port = Integer.parseInt(args[0].substring(c + 1));

					List<X509Certificate> certs = certsFromServer(host, port);
					String alias = getDN(certs.get(0).getSubjectX500Principal());
					X509KeyManager km = main.cloneCertificates(alias, certs);

					outputKeyAndCertificate(alias, km, out);
				} else {
					System.err
							.println("Certificate file "
									+ src
									+ " not found, and it doesn't look like a host:port");
				}
			} else {
				List<X509Certificate> certs = certsFromStream(new FileInputStream(
						src));
				String alias = getDN(certs.get(0).getSubjectX500Principal());
				X509KeyManager km = main.cloneCertificates(alias, certs);

				outputKeyAndCertificate(alias, km, out);
			}
		}

		Enumeration<String> aliases = keystore.aliases();
		if (dst != null && aliases.hasMoreElements()) {
			keystore.store(new FileOutputStream(dst), ksp);
			System.err
					.println("Provided keystore now has the following aliases:");
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				System.err.println("Alias: " + alias + ", added "
						+ keystore.getCreationDate(alias));
			}

		}
	}
}
