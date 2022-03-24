package de.trustable.scep.client.scepClient;

import de.trustable.util.CryptoUtil;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.client.Client;
import org.jscep.client.ClientException;
import org.jscep.client.EnrollmentResponse;
import org.jscep.client.verification.CertificateVerifier;
import org.jscep.transaction.TransactionException;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;


/**
 * Simple SCEP Client to request or revoke a certificate using the SCEP protocol, based on jscep
 *
 */
public class SCEPClient {

	private String scepSecret = "foo123";
	private int keyLength;
	private String caUrl = "http://localhost:8080/ca3sScep/test";
	private String keystoreAlias = "test";
	private char[] keystorePassphrase;
	private KeyStore keystore;
	private File keystoreFile;
	private KeyStore truststore;

	private boolean verifyCertificates;
	private boolean verbose = false;


	private SCEPClient() {

		java.security.Security.addProvider( new BouncyCastleProvider() );
	}
	
	public SCEPClient(String caUrl, String scepSecret, int keyLength,
					  String keystoreAlias, char[] keystorePassphrase,
					  KeyStore keystore, File keystoreFile,
					  boolean verifyCertificates,
					  KeyStore truststore,
					  boolean verbose ) {
		this();
		
		this.caUrl = caUrl;
		this.scepSecret = scepSecret;
		this.keyLength = keyLength;
		this.keystore = keystore;
		this.keystoreAlias = keystoreAlias;
		this.keystorePassphrase = keystorePassphrase;
		this.keystoreFile = keystoreFile;
		this.verifyCertificates = verifyCertificates;
		this.truststore = truststore;
		this.verbose = verbose;
	}


	public static void main(String[] args) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {

		int ret = handleArgs(args);

		if( ret != 0) {
			System.exit(ret);
		}

	}
	
	public static int handleArgs(String[] args) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
	
		String caUrl = null;
		String scepSecret = null;
		String keystoreAlias = null;
		String requestedDN = "CN=test certificate";
		List<GeneralName> gnList = new ArrayList<>();
		String keyLengthString = "2048";
		String keystoreFilename = "keystore.p12";
		String keystoreType = "PKCS12";
		char[] keystorePassphrase = null;

		String truststoreFilename = "";
		String truststoreType = "PKCS12";
		char[] truststorePassphrase = "changeit".toCharArray();

		boolean verifyCertificates = true;
		boolean verbose = false;


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
			} else if( "-i".equals(arg)) {
				verifyCertificates = false;
			} else if( "-v".equals(arg)) {
				verbose = true;
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
					} else if( "-n".equals(arg)) {
						gnList.add(new GeneralName(GeneralName.dNSName, nArg));
					} else if( "-l".equals(arg)) {
						keyLengthString = nArg;
					} else if( "-k".equals(arg)) {
						keystoreFilename = nArg;
					} else if( "-p".equals(arg)) {
						keystorePassphrase = nArg.toCharArray();
					} else if( "-tf".equals(arg)) {
						truststoreFilename = nArg;
					} else if( "-tt".equals(arg)) {
						truststoreType = nArg;
					} else if( "-tp".equals(arg)) {
						truststorePassphrase = nArg.toCharArray();
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

		KeyStore truststore = null;

		if( truststoreFilename != null && !truststoreFilename.trim().isEmpty()) {
			truststore = KeyStore.getInstance(truststoreType);
			File truststoreFile = new File(truststoreFilename);
			if (!truststoreFile.exists()) {
				System.err.println("truststore file '" + truststoreFilename + "' does not exist! Exiting ...");
				return 1;
			} else {

				if (!truststoreFile.canRead()) {
					System.err.println("No read access to truststore file '" + truststoreFilename + "'! Exiting ...");
					return 1;
				}

				try (FileInputStream tis = new FileInputStream(truststoreFile)) {
					truststore.load(tis, truststorePassphrase);
				}
			}
		}

		int keyLength = Integer.parseInt(keyLengthString);
		try {
			SCEPClient client = new SCEPClient( caUrl, scepSecret, keyLength, keystoreAlias, keystorePassphrase, keystore, keystoreFile, verifyCertificates,
					truststore,
				verbose);
			client.signCertificateRequest(requestedDN, gnList.toArray(new GeneralName[0]));
		} catch(GeneralSecurityException | IOException | TransactionException | ClientException ex) {
			System.err.println("problem occurred: " + ex.getLocalizedMessage());
		}

		return 0;
	}

	static void printHelp() {
		System.out.println("\nSimple SCEP Client\n");
		
		System.out.println("Options:\n");
		System.out.println("-h\t\tPrint help (optional)");
		
		System.out.println("\nArguments:\n");
		System.out.println("-u caURL\tCA URL (required)");
		System.out.println("-s secret\tSCEP access secret (required)");
		System.out.println("-l key length\tkey length (default: 2048)");
		System.out.println("-k keystore\tfile name of the keystore (required)");
		System.out.println("-p passphrase\tpassphrase of the keystore (required)");
		System.out.println("-a alias\talias of the keystore element (required)");
		System.out.println("-d DN\tdistinguished name of the certificate to be created");

		System.out.println("-tf truststore\tfile name of the truststore");
		System.out.println("-tt truststore type\tcontainer type of truststore, default: 'PKCS12'");
		System.out.println("-tp truststore passphrase\tpassphrase of truststore, default: 'changeit'");

		System.out.println("-i ignore\tignore certificate validation problems, make truststore settings redundant");
		System.out.println("-v verbose\tenable verbose log output");

	}

	X509Certificate signCertificateRequest(final String requestedDN, final GeneralName[] sanArr)
			throws GeneralSecurityException, IOException, TransactionException, ClientException {

		X500Principal requestedPrincipal = new X500Principal(requestedDN);
		X500Principal enrollingPrincipal = new X500Principal("CN=SCEPRequested_" + System.currentTimeMillis() + ",O=trustable solutions,C=DE");
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(keyLength);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		X509Certificate ephemeralCert = X509Certificates.createEphemeral(enrollingPrincipal, keyPair);


		Client client = getClient();

		trace("ephemeralCert : " + ephemeralCert);

		PKCS10CertificationRequest csr = CryptoUtil.getCsr(requestedPrincipal,
				keyPair.getPublic(),
				keyPair.getPrivate(),
				this.scepSecret.toCharArray(),
				null,
				sanArr);

		EnrollmentResponse resp = client.enrol(ephemeralCert, keyPair.getPrivate(), csr);

		if(resp.isFailure()) {
			log("request failed: " + resp.getFailInfo() );
			throw new ClientException(resp.getFailInfo().toString());
		}


		while (resp.isPending()){
			try {
				TimeUnit.SECONDS.sleep(1);
			} catch (InterruptedException e) {
				trace("InterruptedException: " + e.getMessage() );
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

	Client getClient() throws MalformedURLException {
		URL serverUrl = new URL(caUrl);
		trace("scep serverUrl : " + serverUrl);

		CertificateVerifier trustAllCertificateVerifier = new CertificateVerifier() {
			@Override
			public boolean verify(X509Certificate x509Certificate) {
				return true;
			}
		};

		Client trustAllClient = new Client(serverUrl, trustAllCertificateVerifier);

		if(verifyCertificates){
			CertificateVerifier certificateVerifier = new CertificateVerifier() {
				@Override
				public boolean verify(X509Certificate x509Certificate) {

					try {
						TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
						tmf.init(truststore);
						X509TrustManager tm = (X509TrustManager) tmf.getTrustManagers()[0];
						X509Certificate[] certArr = new X509Certificate[1];
						certArr[0] = x509Certificate;
						tm.checkClientTrusted(certArr, "RSA");
						return true;
					} catch ( NoSuchAlgorithmException | KeyStoreException | CertificateException e) {
						warn("scep server certificate verification failed", e);
					}
					return false;
				}
			};
			return new Client(serverUrl, certificateVerifier);
		}else {
			warn("INSECURE OPERATION : CA certificates not verified!");
			return trustAllClient;
		}
	}

	void warn(String msg){
		System.err.println(msg);
	}

	void warn(String msg, Exception e){
		System.err.println(msg);
		e.printStackTrace();
	}

	void log(String msg){
		System.out.println(msg);
	}

	void log(String msg, Exception e){
		System.out.println(msg);
		e.printStackTrace();
	}

	void trace(String msg){
		if(verbose) {
			System.out.println(msg);
		}
	}

}
