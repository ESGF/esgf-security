package esg.security.utils.ssl;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.xml.signature.impl.X509CertificateBuilder;

import com.sun.net.ssl.internal.ssl.SSLContextImpl;

public class CertUtilsTest {
	private static boolean running = true;
	private static ServerSocket ssocket;
	
	@BeforeClass
	public static void setupOnce() throws Exception {
		KeyPair kp = TrivialCertGenerator.generateRSAKeyPair();
		Certificate selfSigned = TrivialCertGenerator.createSelfSignedCertificate(kp, "CN=test-server,L=DE");
		final KeyStore ks = TrivialCertGenerator.packKeyStore(null, new Certificate[]{selfSigned}, kp.getPrivate(), null);

		
		new Thread(new Runnable() {

			@Override
			public void run() {
				System.out.println("Test SSL Server init.");
				int port = 9443;
				while (running) {
					try {
						SSLContext sc = SSLContext.getInstance("SSL");
						KeyManagerFactory kmf =
                            KeyManagerFactory.getInstance("SunX509");
						kmf.init(ks, "changeit".toCharArray());
						sc.init(kmf.getKeyManagers(), null, new SecureRandom());
						ServerSocketFactory ssocketFactory = SSLServerSocketFactory
								.getDefault();
						ssocket = ssocketFactory
								.createServerSocket(port);
						// Listen for connections
						System.out.println("Waiting for first connection.");
						ssocket.accept();
						System.out.println("Got connection.");
						Thread.sleep(5000);
						running=false;
					} catch (BindException e) {
						running = false;
						e.printStackTrace();
					} catch (Exception e) {
						e.printStackTrace();
					}

				}
				System.out.println("Test SSL Server shut down.");
			}
			
		}).start();
	}
	
	@AfterClass
	public static void tearOnce() {
		running = false;
		try {
			ssocket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testRetrieveCertificates() throws Exception {
		String urlRight = "https://localhost:9443";
		CertPath cp = CertUtils.retrieveCertificates(urlRight, false);
		assertNotNull(cp);
		assertTrue(cp.getCertificates().size() > 0);

		for (Certificate c : cp.getCertificates()) {
			X509Certificate cert = (X509Certificate) c;
			System.out.println(cert.getIssuerDN() + " -> "
					+ cert.getSubjectDN());
		}

	}

}
