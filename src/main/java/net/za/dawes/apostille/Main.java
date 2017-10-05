package net.za.dawes.apostille;


import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;
import java.util.Enumeration;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
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
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Main {

	public static void cloneCertificates(KeyStore ks, String alias, X509Certificate[] certs, char[] keyPassword) throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, KeyStoreException, CertificateException {
		PrivateKey caKey = null;

		X509Certificate[] myCerts = new X509Certificate[certs.length];
		try {
			for (int i = certs.length - 1; i >= 0; i--) {
				// generate a key pair that matches the certificates public key
				KeyPair keyPair = generateKeyPair(certs[i].getPublicKey());

				if (caKey == null) {
					if (!certs[i].getIssuerX500Principal().equals(certs[i].getSubjectX500Principal())) {
						try {
							String caCN = getCN(certs[i].getIssuerX500Principal());
							caKey = (PrivateKey) ks.getKey(caCN, keyPassword);
							if (caKey == null) {
								X509Certificate caCert = getCaCertificate(caCN);
								if (caCert != null) {
									cloneCertificates(ks, null, new X509Certificate[] {caCert}, keyPassword);
									caKey = (PrivateKey) ks.getKey(caCN, keyPassword);
								}
							}
							if (caKey == null)
								throw new CertificateException("Couldn't get caKey");
						} catch (UnrecoverableKeyException e) {
							throw new CertificateException(e);
						}
					} else {
						caKey = keyPair.getPrivate();
					}
				}

				Date startDate = certs[i].getNotBefore();
				Date expiryDate = certs[i].getNotAfter();
				BigInteger serialNumber = certs[i].getSerialNumber();

				X509v3CertificateBuilder generator = new JcaX509v3CertificateBuilder(certs[i].getIssuerX500Principal(),
						serialNumber, startDate, expiryDate, certs[i].getSubjectX500Principal(), keyPair.getPublic());

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

				Certificate[] chain = new Certificate[certs.length - i];
				System.arraycopy(myCerts, i, chain, 0, chain.length);

				String cn = getCN(cert.getSubjectX500Principal());
				ks.setKeyEntry(alias != null ? alias : cn, keyPair.getPrivate(), keyPassword, chain);
			}
		} catch (RuntimeException | AnnotatedException | CertIOException e) {
			throw new CertificateException(e);
		}
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

	private static void clone(KeyStore src, KeyStore dst, char[] kp) throws Exception {
		Enumeration<String> aliases = src.aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			System.out.println("Copying " + alias);
			X509Certificate[] certs = copy(src.getCertificateChain(alias));
			cloneCertificates(dst, alias, certs, kp);
		}
	}
	
	public static void main(String[] args) throws Exception {
		if (args.length < 4) {
			System.out.println("Usage: java -jar apostille.jar src.jks dst.jks <keystore_password> <key_password>");
			System.exit(0);
		}
		File src = new File(args[0]);
		File dst = new File(args[1]);
		char[] ksp = args[2].toCharArray();
		char[] kp = args[3].toCharArray();
		KeyStore srcKs = KeyStore.getInstance(KeyStore.getDefaultType());
		srcKs.load(new FileInputStream(src), ksp);
		
		KeyStore dstKs = KeyStore.getInstance(KeyStore.getDefaultType());
		dstKs.load(null, ksp);
		
		clone(srcKs, dstKs, kp);
		
		dstKs.store(new FileOutputStream(dst), ksp);
	}
}
