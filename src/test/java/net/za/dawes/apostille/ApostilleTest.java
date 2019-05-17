package net.za.dawes.apostille;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.internal.ArrayComparisonFailure;

public class ApostilleTest {

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
    }

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void test() throws KeyStoreException, CertificateException, IOException, UnrecoverableKeyException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, OperatorCreationException, AnnotatedException,
            CertPathValidatorException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        Apostille apostille = new Apostille(ks, "password".toCharArray());
        testSite(apostille, "google.com.pem");
        dumpKeystore(ks);
        testSite(apostille, "cnn.com.pem");
        dumpKeystore(ks);
    }

    public void testSite(Apostille apostille, String pem) throws KeyStoreException, CertificateException, IOException,
            UnrecoverableKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            OperatorCreationException, AnnotatedException, CertPathValidatorException {
        InputStream in = getClass().getResourceAsStream(pem);

        X509Certificate[] certs = Apostille.certsFromStream(in);
        String dn = apostille.cloneCertificates(certs);
        X509Certificate[] cloned = apostille.getKeyManager(dn).getCertificateChain(dn);
        Assert.assertEquals(cloned.length, certs.length);
        for (int i = 0; i < cloned.length; i++) {
            compare(i, certs, cloned);
            // compareLines(certs[i].toString(), cloned[i].toString());
        }

        X509Certificate ca = apostille.getCaCertificate(cloned);
        validate(cloned, ca);
    }

    private void validate(X509Certificate[] path, X509Certificate ca)
            throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertPathValidatorException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertPath cp = cf.generateCertPath(Arrays.asList(path));

        TrustAnchor anchor = new TrustAnchor(ca, null);
        PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
        params.setRevocationEnabled(false);
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
        cpv.validate(cp, params);
    }

    private void dumpKeystore(KeyStore ks) throws KeyStoreException, CertificateParsingException {
        Enumeration<String> aliases = ks.aliases();
        if (aliases.hasMoreElements()) {
            System.err.println("Keystore has the following entries:");
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate[] certs = ks.getCertificateChain(alias);
                System.err.println(
                        "Alias: " + alias + ", added " + ks.getCreationDate(alias) + " - chain length " + certs.length);
                X509Certificate cert = (X509Certificate) certs[0];
                Collection<List<?>> san = cert.getSubjectAlternativeNames();
                if (san != null) {
                    List<String> names = new ArrayList<>();
                    for (List<?> l : san) {
                        Integer gn = (Integer) l.get(0);
                        if (gn.equals(2) || gn.equals(7)) {
                            names.add((String) l.get(1));
                        }
                    }
                    if (names.size() > 0) {
                        System.err.println("\tAlternate names: " + names);
                    }
                }
            }
        }
    }

    private void compare(int index, X509Certificate[] a, X509Certificate[] b) {
        try {
            X509Certificate one = a[index], two = b[index];
            try {
                Assert.assertArrayEquals(one.getSignature(), two.getSignature());
                Assert.fail("Arrays must NOT be equal!");
            } catch (ArrayComparisonFailure e) {
            }
            Assert.assertEquals(one.getSubjectX500Principal(), two.getSubjectX500Principal());
            Assert.assertEquals(one.getIssuerX500Principal(), two.getIssuerX500Principal());
            Assert.assertEquals(one.getSigAlgName(), two.getSigAlgName());
        } catch (Throwable e) {
            System.err.println("Failed comparing " + index);
            throw e;
        }
    }

    private boolean isHex(char c) {
        return ('0' <= c && c <= '9') || ('A' <= c && c <= 'F') || ('a' <= c && c <= 'f');
    }

    private void compareLines(String one, String two) {
        String[] ones = one.split("\n");
        String[] twos = two.split("\n");
        Assert.assertEquals(ones.length, twos.length);
        for (int i = 0; i < ones.length; i++) {
            try {
                compareIgnoringHexNibbles(ones[i], twos[i]);
                System.err.println("  " + ones[i]);
                System.err.flush();
            } catch (AssertionError e) {
                System.out.println("< " + ones[i] + "\n> " + twos[i]);
                System.out.flush();
            }
        }
    }

    private void compareIgnoringHexNibbles(String one, String two) {
        Assert.assertEquals(one.length(), two.length());
        for (int i = 0; i < one.length(); i++) {
            char o = one.charAt(i);
            char t = two.charAt(i);
            if (o == t) {
                continue;
            } else if (isHex(o) && isHex(t)) {
                continue;
            } else {
                Assert.assertEquals("Strings differ at position " + i, o, t);
            }
        }
    }
}
