/*******************************************************************************
 * Copyright (c) 2011 Earth System Grid Federation
 * ALL RIGHTS RESERVED. 
 * U.S. Government sponsorship acknowledged.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 
 * Neither the name of the <ORGANIZATION> nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package esg.security.utils.ssl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;

import org.apache.commons.lang.ArrayUtils;

import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.KeyIdentifier;
import sun.security.x509.SubjectKeyIdentifierExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

/**
 * Managed the creation of simple X509 Certificates, Chains, etc.
 */
public class TrivialCertGenerator {
    private static int serial = 1;
    private static ObjectIdentifier algorithm = AlgorithmId.sha1WithRSAEncryption_oid;

    /**
     * Sign a certificate with another. This does not guarantee the signing
     * certificate is a CA (it is if created by
     * {@link #createSelfSignedCertificate(KeyPair, String)}
     * 
     * @param ca ca used for signing
     * @param caKey ca private key for signing.
     * @param cert certificate that will get signed
     * @return a signed certificate
     * @throws Exception
     */
    public static X509CertImpl sign(X509CertImpl ca, PrivateKey caKey,
            X509CertImpl cert) throws Exception {
        // retrieve all info from both certs
        X509CertInfo certInfo = (X509CertInfo) cert.get(X509CertImpl.NAME + "."
                + X509CertImpl.INFO);
        X509CertInfo caCertInfo = (X509CertInfo) ca.get(X509CertImpl.NAME + "."
                + X509CertImpl.INFO);

        // Set the issuer
        X500Name issuer = (X500Name) caCertInfo.get(X509CertInfo.SUBJECT + "."
                + CertificateIssuerName.DN_NAME);
        certInfo.set(
                X509CertInfo.ISSUER + "." + CertificateSubjectName.DN_NAME,
                issuer);

        certInfo.set(CertificateAlgorithmId.NAME + "."
                + CertificateAlgorithmId.ALGORITHM, new AlgorithmId(algorithm));

        // if you alter the extension you'll have to copy every other extension
        // from the
        // original cert. Better leave it like it is.

        X509CertImpl newCert = new X509CertImpl(certInfo);
        newCert.sign(caKey, algorithm.toString());
        return newCert;
    }

    /**
     * Generate a keypair using the RSA algorithm.
     * 
     * @return a keypair generated by the RSA algorithm
     * @throws NoSuchAlgorithmException If RSA is not supported
     * @throws Exception
     */
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(1024, new SecureRandom());
        return kpGen.generateKeyPair();
    }

    /**
     * @param kp KeyPair storing the keys for this certificate
     * @param DN The DN used when generating
     * @return an X509CertInfo with the basic data for creating a self-signed CA
     *         with a 10 year validity from now.
     * @throws CertificateException if some certificate value could not be set
     * @throws IOException If some objects couldn't be created (e.g. DN is not
     *             well-formed)
     */
    public static X509CertInfo getDefaultInfo(KeyPair kp, String DN)
            throws CertificateException, IOException {
        // prepare certificate info
        X509CertInfo info = new X509CertInfo();
        // seral number
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(
                serial++));
        // validity
        info.set(
                X509CertInfo.VALIDITY,
                new CertificateValidity(new Date(), new Date(new Date()
                        .getTime() + 10 * 365 * 24 * 60 * 60 * 1000L)));
        // cersion v3
        info.set(X509CertInfo.VERSION, new CertificateVersion(2));
        // public key
        info.set(X509CertInfo.KEY, new CertificateX509Key(kp.getPublic()));
        // the signing algorithm
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(
                new AlgorithmId(algorithm)));
        // subject == issuer
        X500Name subject = new X500Name(DN);
        info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(subject));
        info.set(X509CertInfo.ISSUER, new CertificateIssuerName(subject));
        // extensions
        CertificateExtensions ext = new CertificateExtensions();
        ext.set(SubjectKeyIdentifierExtension.NAME,
                new SubjectKeyIdentifierExtension(new KeyIdentifier(kp
                        .getPublic()).getIdentifier()));
        // a CA with no limit
        ext.set(BasicConstraintsExtension.IS_CA, new BasicConstraintsExtension(
                true, -1));
        info.set(X509CertInfo.EXTENSIONS, ext);

        return info;
    }

    /**
     * Create a self signed certificate with the provided keys and DN. The
     * certificate is a CA that can sign other certs.
     * 
     * @param kp KeyPair storing the keys for this certificate
     * @param DN The DN used when generating
     * @return The created certificate
     * @throws CertificateException if some certificate value could not be set
     * @throws IOException If some objects couldn't be created (e.g. DN is not
     *             well-formed)
     * @throws SignatureException Signature Failed.
     * @throws NoSuchProviderException No SunX509Provider in here.
     * @throws NoSuchAlgorithmException No {{@value #algorithm} value in here.
     * @throws InvalidKeyException Invalid key type.
     */
    public static X509CertImpl createSelfSignedCertificate(KeyPair kp, String DN)
            throws CertificateException, IOException, InvalidKeyException,
            NoSuchAlgorithmException, NoSuchProviderException,
            SignatureException {

        // prepare certificate info
        X509CertInfo info = getDefaultInfo(kp, DN);

        // create cert
        X509CertImpl cert = new X509CertImpl(info);
        // sign
        cert.sign(kp.getPrivate(), algorithm.toString());

        return createCertificate(getDefaultInfo(kp, DN), kp.getPrivate());
    }

    /**
     * Create a certificate with the provided certificate info and private key.
     * The private key must be the match of the public key contained in the
     * certificate info although this won't be checked.
     * 
     * @param kp KeyPair storing the keys for this certificate
     * @param DN The DN used when generating
     * @return The created certificate
     * @throws CertificateException if some certificate value could not be set
     * @throws IOException If some objects couldn't be created (e.g. DN is not
     *             well-formed)
     * @throws SignatureException Signature Failed.
     * @throws NoSuchProviderException No SunX509Provider in here.
     * @throws NoSuchAlgorithmException No {{@value #algorithm} value in here.
     * @throws InvalidKeyException Invalid key type.
     */
    public static X509CertImpl createCertificate(X509CertInfo certInfo,
            PrivateKey pk) throws CertificateException, IOException,
            InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException {

        // create cert
        X509CertImpl cert = new X509CertImpl(certInfo);
        // sign
        cert.sign(pk, algorithm.toString());

        return cert;
    }

    /**
     * @param keystore keystore in PKIX
     * @param pass the keystore password.
     * @return
     * @throws IOException if file cannot be opend
     * @throws KeyStoreException keystore format not supported
     * @throws NoSuchAlgorithmException keystore format not supported
     * @throws CertificateException if any of the certificates in the keystore
     *             could not be loaded.
     */
    public static KeyStore loadKeystore(File keystore, String pass)
            throws IOException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException {

        KeyStore ks = KeyStore.getInstance("JKS");
        InputStream in = new FileInputStream(keystore);
        char[] passphrase = (pass == null) ? null : pass.toCharArray();
        ks.load(in, passphrase);

        in.close();

        return ks;
    }

    /**
     * One method for everything, not perfect but it does the work for the time
     * being.
     * 
     * @param ks KeyStore to use, if null a new one with pass "changeit" will be
     *            created
     * @param chain certificate chain to use for the private key (if null no
     *            private cert set)
     * @param key private key (if null no private cert set)
     * @param trusted trusted certificates to add to this trustore
     * @return the created trustore
     * @throws KeyStoreException If the certificates cannot be added to
     *             keystore/truststore.
     */
    public static KeyStore packKeyStore(KeyStore ks, Certificate[] chain,
            PrivateKey key, Certificate[] trusted) throws KeyStoreException {
        if (ks == null) {
            try {
                ks = KeyStore.getInstance("JKS");
            } catch (KeyStoreException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            // this initializes the trustore, it doesn't matter if it's empty
            // this is required.
            try {
                ks.load(null, "changeit".toCharArray());
            } catch (NoSuchAlgorithmException e) {
                // can't happen
            } catch (CertificateException e) {
                // can't happen
            } catch (IOException e) {
                // can't happen
            }
        }
        if (chain != null && key != null) {
            if (chain.length > 1) {
                // check the order is right
                try {
                    chain[0].verify(chain[1].getPublicKey());
                } catch (SignatureException e) {
                    // order is probably wrong! Correct it.
                    chain = chain.clone();
                    ArrayUtils.reverse(chain);
                    // we might assure the chain is valid indeed..

                } catch (Exception e) {
                    // don't care at this point
                }

            }
            // save key
            ks.setKeyEntry("myKey", key, "changeit".toCharArray(), chain);
        }
        if (trusted != null) {
            for (int i = 0; i < trusted.length; i++) {
                ks.setCertificateEntry("trusted" + i, trusted[i]);
            }
        }
        return ks;
    }
}
