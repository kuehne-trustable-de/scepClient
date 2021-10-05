package de.trustable.scep.client.scepClient;

import de.trustable.util.CryptoUtil;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.client.Client;
import org.jscep.client.ClientException;
import org.jscep.client.EnrollmentResponse;
import org.jscep.client.verification.CertificateVerifier;
import org.jscep.transaction.TransactionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.TimeUnit;


/**
 * Simple SCEP Client to request or revoke a certificate using the SCEP protocol, based on jscep
 *
 */
public class SCEPClient {

	private static final Logger LOGGER = LoggerFactory.getLogger(SCEPClient.class);
	public static final java.lang.String REQUEST = "Request";
	public static final java.lang.String REVOKE = "Revoke";

	SecureRandom secRandom = new SecureRandom();

	private String scepSecret = "foo123";
	private String caUrl = "http://localhost:8080/ca3sScep/test";
	private String keystoreAlias = "test";
	private char[] keystorePassphrase;
	private KeyStore keystore;
	private File keystoreFile;


	private SCEPClient() {
        java.security.Security.addProvider( new BouncyCastleProvider() );
	}
	
	public SCEPClient(String caUrl, String scepSecret, String keystoreAlias, char[] keystorePassphrase, KeyStore keystore, File keystoreFile) {
		this();
		
		this.caUrl = caUrl;
		this.scepSecret = scepSecret;
		this.keystore = keystore;
		this.keystoreAlias = keystoreAlias;
		this.keystorePassphrase = keystorePassphrase;
		this.keystoreFile = keystoreFile;
	}


	public static void main(String[] args) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {

		int ret = handleArgs(args);

		if( ret != 0) {
			System.exit(ret);
		}

	}
	
	public static int handleArgs(String[] args) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
	
		String mode = "Request";

		String caUrl = null;
		String scepSecret = null;
		String keystoreAlias = null;
		String reason = "unspecified";
		String requestedDN = "CN=test certificate";
		String keystoreFilename = "keystore.p12";
		String keystoreType = "PKCS12";
		char[] keystorePassphrase = null;
		String certFile = "test.crt";

		if( args.length == 0) {
			printHelp();
			return 1;
		}
		
		for( int i = 0; i < args.length; i++) {
			String arg = args[i];
			boolean nextArgPresent = (i + 1 < args.length);
			
			if( "-h".equals(arg)) {
				printHelp();
				return 0;
			} else {
				if( nextArgPresent ) {
					i++;
					String nArg = args[i];
					if( "-u".equals(arg)) {
						caUrl = nArg;
					} else if( "-s".equals(arg)) {
						scepSecret = nArg;
					} else if( "-a".equals(arg)) {
						keystoreAlias = nArg;
					} else if( "-d".equals(arg)) {
						requestedDN = nArg;
					} else if( "-k".equals(arg)) {
						keystoreFilename = nArg;
					} else if( "-p".equals(arg)) {
						keystorePassphrase = nArg.toCharArray();
					}

				}else {
					System.err.println("option '" + arg + "' requires argument!");
				}
			}
		}

		if(caUrl == null) {
			System.err.println("'caUrl' must be provided! Exiting ...");
			return 1;
		}

		if(scepSecret == null) {
			System.err.println("'scepSecret' must be provided! Exiting ...");
			return 1;
		}

		if(keystoreAlias == null) {
			System.err.println("'keystoreAlias' must be provided! Exiting ...");
			return 1;
		}

		if(keystorePassphrase == null) {
			System.err.println("'keystorePassphrase' must be provided! Exiting ...");
			return 1;
		}


		KeyStore keystore = KeyStore.getInstance(keystoreType);
		File keystoreFile = new File(keystoreFilename);
		if( !keystoreFile.exists()) {
			System.out.println("Creating keystore file '" + keystoreFilename + "'.");
			keystore.load(null, keystorePassphrase);
		}else {

			if (!keystoreFile.canRead()) {
				System.err.println("No read access to keystore file '" + keystoreFilename + "'! Exiting ...");
				return 1;
			}
			if (!keystoreFile.canWrite()) {
				System.err.println("No write access to keystore file '" + keystoreFilename + "'! Exiting ...");
				return 1;
			}

			try(FileInputStream kis = new FileInputStream(keystoreFile)){
				keystore.load(kis, keystorePassphrase);
			}
		}

		try {
			SCEPClient client = new SCEPClient( caUrl, scepSecret, keystoreAlias, keystorePassphrase, keystore, keystoreFile);
			client.signCertificateRequest(requestedDN);
		} catch(GeneralSecurityException | IOException | TransactionException | ClientException ex) {
			System.err.println("problem occured: " + ex.getLocalizedMessage());
		}

		return 0;
	}

	private static void printHelp() {
		System.out.println("\nSimple SCEP Client\n");
		
		System.out.println("Options:\n");
		System.out.println("-h\t\tPrint help (optional)");
		
		System.out.println("\nArguments:\n");
		System.out.println("-u caURL\tCA URL (required)");
		System.out.println("-s secret\tSCEP access secret (required)");
		System.out.println("-k keystore\tfile name of the keystore (required)");
		System.out.println("-p passphrase\tpassphrase of the keystore (required)");
		System.out.println("-a alias\talias of the keystore element (required)");
		System.out.println("-d DN\tdestinguished name of the certificate to be created");
		
	}

	public X509Certificate signCertificateRequest(final String requestedDN)
			throws GeneralSecurityException, IOException, TransactionException, ClientException {

		X500Principal requestedPrincipal = new X500Principal(requestedDN);
		X500Principal enrollingPrincipal = new X500Principal("CN=SCEPRequested_" + System.currentTimeMillis() + ",O=trustable solutions,C=DE");
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		X509Certificate ephemeralCert = X509Certificates.createEphemeral(enrollingPrincipal, keyPair);


		Client client = getClient();

		LOGGER.info("ephemeralCert : " + ephemeralCert);

		PKCS10CertificationRequest csr = CryptoUtil.getCsr(requestedPrincipal,
				keyPair.getPublic(),
				keyPair.getPrivate(),
				this.scepSecret.toCharArray());

		EnrollmentResponse resp = client.enrol(ephemeralCert, keyPair.getPrivate(), csr);

		if(resp.isFailure()) {
			LOGGER.info("request failed: " + resp.getFailInfo() );
			throw new ClientException(resp.getFailInfo().toString());
		}


		while (resp.isPending()){
			try {
				TimeUnit.SECONDS.sleep(1);
			} catch (InterruptedException e) {
				LOGGER.info("InterruptedException: " + e.getMessage() );
			}
			resp = client.poll(ephemeralCert, keyPair.getPrivate(), new X500Principal(csr.getSubject().toString()), resp.getTransactionId());
		}

		if (resp.isSuccess()) {

			CertStore certStore = resp.getCertStore();

			Collection<? extends java.security.cert.Certificate> collCerts = certStore.getCertificates(new AcceptAllCertSelector());

			Certificate[] certArr = new Certificate[collCerts.size()];
			X509Certificate cert = (X509Certificate)(certStore.getCertificates(new AcceptEndEntityCertSelector()).iterator().next());
			certArr[0] = cert;
			for( int i = 1; i < collCerts.size(); i++){
				certArr[i] = certStore.getCertificates(new AcceptIssuerCertSelector(certArr[i-1])).iterator().next();
			}

			keystore.setKeyEntry(this.keystoreAlias, keyPair.getPrivate(), keystorePassphrase, certArr);

			try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
				keystore.store(fos, keystorePassphrase);
			}

			return (X509Certificate) collCerts.toArray()[0];
		}
		throw new ClientException("request failed, no certificate returned");
	}

	private Client getClient() throws MalformedURLException {
		URL serverUrl = new URL(caUrl);
		LOGGER.debug("scep serverUrl : " + serverUrl);

		CertificateVerifier acceptAllVerifier = new AcceptAllVerifier();
		return new Client(serverUrl, acceptAllVerifier);
	}

}
