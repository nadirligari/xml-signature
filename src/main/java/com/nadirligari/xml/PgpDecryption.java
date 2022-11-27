package com.nadirligari.xml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

public class PgpDecryption {

	public static byte[] decrypt(byte[] encrypted, PGPPrivateKey privateKey, String password) throws Exception {
		
		try (InputStream in = new ByteArrayInputStream(encrypted); InputStream inn = PGPUtil.getDecoderStream(in)) {

			PGPObjectFactory pgpF = new PGPObjectFactory(inn, new JcaKeyFingerprintCalculator());
			PGPEncryptedDataList enc = null;
			Object o = pgpF.nextObject();

			if (o instanceof PGPEncryptedDataList) {
				enc = (PGPEncryptedDataList) o;
			} else {
				enc = (PGPEncryptedDataList) pgpF.nextObject();
			}

			Iterator it = enc.getEncryptedDataObjects();
			PGPPublicKeyEncryptedData pbe = null;

			while (pbe == null && it.hasNext()) {
				pbe = (PGPPublicKeyEncryptedData) it.next();
			}

			InputStream clear = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(privateKey));
			PGPObjectFactory pgpFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
			PGPCompressedData cData = (PGPCompressedData) pgpFact.nextObject();
			pgpFact = new PGPObjectFactory(cData.getDataStream(), new JcaKeyFingerprintCalculator());
			PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();
			InputStream unc = ld.getInputStream();
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			
			int ch;
			while ((ch = unc.read()) >= 0) {
				out.write(ch);
			}
			
			byte[] returnBytes = out.toByteArray();
			out.close();
			return returnBytes;
		}
		
	}

}