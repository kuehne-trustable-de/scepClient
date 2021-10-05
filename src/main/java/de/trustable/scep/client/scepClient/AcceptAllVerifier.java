package de.trustable.scep.client.scepClient;

import org.jscep.client.verification.CertificateVerifier;

import java.security.cert.X509Certificate;

/**
 * NEVER use this in a production-like environment!!!
 * 
 * @author kuehn
 *
 */
public class AcceptAllVerifier implements CertificateVerifier{

	@Override
	public boolean verify(X509Certificate arg0) {
		return true;
	}

}
