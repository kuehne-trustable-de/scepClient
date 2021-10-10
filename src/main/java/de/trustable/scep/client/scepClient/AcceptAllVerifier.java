package de.trustable.scep.client.scepClient;

import org.jscep.client.verification.CertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;

/**
 * NEVER use this in a production-like environment!!!
 * 
 * @author kuehn
 *
 */
public class AcceptAllVerifier implements CertificateVerifier{

	private static final Logger LOGGER = LoggerFactory.getLogger(AcceptAllVerifier.class);

	@Override
	public boolean verify(X509Certificate cert) {

		LOGGER.debug("verifying cert '{}'", cert.getSubjectX500Principal().getName());
		return true;
	}

}
