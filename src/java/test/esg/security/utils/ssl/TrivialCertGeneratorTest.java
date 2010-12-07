package esg.security.utils.ssl;

import static org.junit.Assert.*;
import static esg.security.utils.ssl.TrivialCertGenerator.*;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Enumeration;

import javax.crypto.Cipher;

import org.junit.BeforeClass;
import org.junit.Test;

import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;

import esg.security.common.SAMLTestParameters;


public class TrivialCertGeneratorTest {
    private static KeyPair kp;
    
    @BeforeClass
    public static void setupOnce() {
        try {
            kp = generateRSAKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            fail("Cannot initiat tests");
        }
    }
    
    @Test
    public void testSign() throws Exception {
        String rootDN = "CN=Root, OU=TestOU";
        String certDN = "CN=cert, OU=TestOU";
        KeyPair certKey = generateRSAKeyPair();
        
        X509CertImpl root = createSelfSignedCertificate(kp, rootDN);
        root.checkValidity();
        assertEquals(kp.getPublic(), root.getPublicKey());
        
        X509CertImpl cert = createSelfSignedCertificate(certKey, certDN);
        cert.checkValidity();
        assertEquals(certKey.getPublic(), cert.getPublicKey());
        
        X509CertImpl newCert = sign(root, kp.getPrivate(), cert);
        cert.checkValidity();
        assertEquals(certKey.getPublic(), newCert.getPublicKey());
        assertEquals(certDN, newCert.getSubjectDN().toString());
        assertEquals(rootDN, newCert.getIssuerDN().toString());
    }

    @Test
    public void testGenerateRSAKeyPair()  throws Exception {
        try {
            String code = "Message";
            System.out.println("Code: " + code);
            
            //generate the keys
            KeyPair kp = generateRSAKeyPair();
            
            Cipher cEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cEnc.init(Cipher.ENCRYPT_MODE, kp.getPublic());

            Cipher cDec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cDec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            
            byte[] enCode = cEnc.doFinal(code.getBytes("UTF-8"));
            assertNotSame(enCode, code);
            System.out.println("Encoded: " + HexBin.encode(enCode));
            
            String decode = new String(cDec.doFinal(enCode));
            System.out.println("Decoded: " + decode);
            
            assertEquals(code, decode);
            
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            fail("RSA is not supported here.");
        }
        
    }

    @Test
    public void testCreateSelfSignedCertificate() throws Exception {
        String DN = "CN=TestCN, OU=TestOU";
        X509CertImpl cert = createSelfSignedCertificate(kp, DN);
        cert.checkValidity();
        
        assertEquals(DN, cert.getSubjectDN().toString());
        assertEquals(DN, cert.getIssuerDN().toString());
        assertEquals(kp.getPublic(), cert.getPublicKey());
    }
    
    @Test
    public void testCreateCertificateInfo() throws Exception {
        String DN = "CN=TestCN, OU=TestOU";
        //Date now = new Date();
        long now = System.currentTimeMillis();
        
        X509CertInfo info = getDefaultInfo(kp, DN);
        
        //check DN
        assertEquals(DN, info.get(X509CertInfo.SUBJECT).toString());
        
        //check self signed
        assertEquals(DN, info.get(X509CertInfo.ISSUER).toString());
        //check version
        assertEquals(CertificateVersion.V3,
                ((CertificateVersion) info.get(X509CertInfo.VERSION))
                        .get(CertificateVersion.VERSION));
        //check validity
        long notBefore = ((Date) ((CertificateValidity) info
                .get(X509CertInfo.VALIDITY))
                .get(CertificateValidity.NOT_BEFORE)).getTime();
        long notAfter = ((Date) ((CertificateValidity) info
                .get(X509CertInfo.VALIDITY)).get(CertificateValidity.NOT_AFTER)).getTime();
        
        long tenYears = 10 * 365 * 24 * 60 * 60 * 1000L;
        long inTenYears = tenYears + now;

        //check validation start
        assertTrue(notBefore > now - 5 * 1000);
        assertTrue(notBefore < now + 5 * 1000);
        
        //check validation duration
        assertEquals(tenYears, notAfter - notBefore);

        //check validation end
        assertTrue(notAfter > inTenYears - 5 * 1000);
        assertTrue(notAfter < inTenYears + 5 * 1000);
        
        //...more to be checked...
    }
    
    /**
     * CertificateCreationFromInfo: 
     */
    @Test
    public void testCertificateCreationFromInfo() throws Exception {
        String DN = "CN=TestCN, OU=TestOU";
        
        X509CertInfo info = getDefaultInfo(kp, DN);
        
        //change validity
        Date date1 = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L);
        Date date2 = new Date(date1.getTime() + 365 * 24 * 60 * 60 * 1000L);
        info.set(X509CertInfo.VALIDITY, new CertificateValidity(date1,date2));
        
        X509CertImpl c = createCertificate(info, kp.getPrivate());
        assertEquals(date1, c.getNotBefore());
        assertEquals(date2, c.getNotAfter());
        
    }
    
    @Test
    public void testPackKeyStore() throws Exception {
        String rootDN = "CN=Root, OU=TestOU";
        String certDN = "CN=cert, OU=TestOU";
        char[] passphrase = "changeit".toCharArray();
        KeyPair certKey = generateRSAKeyPair();
        
        X509CertImpl root = createSelfSignedCertificate(kp, rootDN);
        X509CertImpl cert = createSelfSignedCertificate(certKey, certDN);
        cert = sign(root, kp.getPrivate(), cert);
        
        //check a simple keystore
        KeyStore ks = packKeyStore(null, new Certificate[]{root}, kp.getPrivate(), null);
        Enumeration<String> aliases = ks.aliases();
        String alias = (String) aliases.nextElement();
        assertFalse(aliases.hasMoreElements());
        Certificate ksCert = ks.getCertificate(alias);
        assertEquals(root, ksCert);
        assertEquals(kp.getPrivate(), ks.getKey(alias, passphrase));
        ksCert.verify(kp.getPublic());
        
        //check a more complex one
        ks = packKeyStore(null, new Certificate[]{root,cert}, certKey.getPrivate(), new Certificate[]{root});
        aliases = ks.aliases();
        alias = (String) aliases.nextElement();
        ksCert = ks.getCertificate(alias);
        alias = (String) aliases.nextElement();
        assertFalse(aliases.hasMoreElements());
        Certificate rootCert;
        if (ksCert.getPublicKey() == kp.getPublic()) {
            //root trusted cert, arrange a little
            rootCert = ksCert;
            ksCert = ks.getCertificate(alias);
        } else {
            rootCert = ks.getCertificate(alias);
            alias = ks.getCertificateAlias(ksCert);
        }
        //rootCert holds the trusted root certificate, ksCert the one with the private key, alias points to ksCert
        assertEquals(root, rootCert);
        assertEquals(cert, ksCert);
        assertEquals(certKey.getPrivate(), ks.getKey(alias, passphrase));
        
        //asure the root signed it
        ksCert.verify(kp.getPublic());
        
        //now for the chain
        Certificate[] chain = ks.getCertificateChain(alias);
        assertEquals(2, chain.length);
        assertEquals(cert, chain[0]);
        assertEquals(root, chain[1]);
        //assure we have no chain in case of the root trusted cert
        assertNull(ks.getCertificateChain(ks.getCertificateAlias(rootCert)));
        
    }
    
    /**
     * LoadKeystore: loads a keystore
     */
    @Test
    public void testLoadKeystore() throws Exception {
        String ksFile = this.getClass()
                .getResource("/" + SAMLTestParameters.KEYSTORE_PATH).getFile();
        assertNotNull(ksFile);
        KeyStore ks = loadKeystore(new java.io.File(ksFile),
                SAMLTestParameters.KEYSTORE_PASSWORD);
        assertNotNull(ks);

        assertTrue(ks.isKeyEntry(SAMLTestParameters.KEYSTORE_ALIAS));
        
    }

}
