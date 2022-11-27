package com.nadirligari.xml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Iterator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.util.encoders.Hex;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class KeyUtils {

	public static PublicKey loadPublicKeyFromCert(byte[] cert) throws CertificateException, IOException {
		X509Certificate certificate = loadCertificate(cert);
		return certificate.getPublicKey();
	}

	public static X509Certificate loadCertificate(byte[] cert) throws CertificateException, IOException {
		try (InputStream fin = new ByteArrayInputStream(cert);) {
			CertificateFactory f = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) f.generateCertificate(fin);
			return certificate;
		}
	}
	
	public static Key loadPublicKey(KeyFactory keyFactory, byte[] keyBytes) throws InvalidKeySpecException {
		// decode public key
		X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyBytes);
		return keyFactory.generatePublic(pubSpec);
	}
	
	public static PublicKey loadPGPPublicKey(byte[] pubKey) throws Exception {
		try (InputStream in = new ByteArrayInputStream(pubKey)) {
			PGPPublicKeyRingCollection pubRings = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in),
					new JcaKeyFingerprintCalculator());
			Iterator<PGPPublicKeyRing> rIt = pubRings.getKeyRings();
			while (rIt.hasNext()) {
				PGPPublicKeyRing pgpPub = rIt.next();
				Iterator<PGPPublicKey> it = pgpPub.getPublicKeys();
				while (it.hasNext()) {
					PGPPublicKey pgpKey = it.next();
					log.debug(pgpKey.getClass().getName() + " KeyID: " + Long.toHexString(pgpKey.getKeyID()) + " type: "
							+ pgpKey.getAlgorithm() + " fingerprint: "
							+ new String(Hex.encode(pgpKey.getFingerprint())));
					{
						PublicKey jceKey = new JcaPGPKeyConverter().getPublicKey(pgpKey);
						return jceKey;
					}
				}
			}
		}
		return null;
	}
	
	public static PrivateKey loadPGPPrivateKey(byte[] privateKey, String passphrase) throws Exception {
        InputStream pgpIn = PGPUtil.getDecoderStream(new ByteArrayInputStream(privateKey));

        PGPObjectFactory pgpFact = new PGPObjectFactory(pgpIn, new JcaKeyFingerprintCalculator());
        PGPSecretKeyRing pgpSecRing = (PGPSecretKeyRing) pgpFact.nextObject();
        PGPSecretKey pgpSec = pgpSecRing.getSecretKey();
        PBESecretKeyDecryptor decryptorFactory = new BcPBESecretKeyDecryptorBuilder(
				new BcPGPDigestCalculatorProvider()).build(passphrase.toCharArray());
        PGPPrivateKey pgpPriv = pgpSec.extractPrivateKey(decryptorFactory);

        JcaPGPKeyConverter converter = new JcaPGPKeyConverter();
        // this is the part i was missing from Peter Dettman's answer. pass BC provider to the converter
        converter.setProvider(new BouncyCastleProvider());
        PrivateKey key = converter.getPrivateKey(pgpPriv);
        return key;
    }
	
	public static PGPPrivateKey getPGPPrivateKey(byte[] privateKey, String passphrase) throws Exception {
        InputStream pgpIn = PGPUtil.getDecoderStream(new ByteArrayInputStream(privateKey));

        PGPObjectFactory pgpFact = new PGPObjectFactory(pgpIn, new JcaKeyFingerprintCalculator());
        PGPSecretKeyRing pgpSecRing = (PGPSecretKeyRing) pgpFact.nextObject();
        PGPSecretKey pgpSec = pgpSecRing.getSecretKey();
        PBESecretKeyDecryptor decryptorFactory = new BcPBESecretKeyDecryptorBuilder(
				new BcPGPDigestCalculatorProvider()).build(passphrase.toCharArray());
        return pgpSec.extractPrivateKey(decryptorFactory);

    }

	
}
