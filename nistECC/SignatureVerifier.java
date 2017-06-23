package com.comarch.cybersecurity.tproecc.ua_sign_library;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import org.bouncycastle.crypto.digests.LongDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.comarch.cybersecurity.tproecc.ua_sign_library.dstu4145.*;
import com.comarch.cybersecurity.tproecc.ua_sign_library.kupyna.Kupyna;
import com.comarch.cybersecurity.tproecc.ua_sign_library.kupyna.KupynaType.EKupynaType;

/**
 * SignatureVerifier provides basic functionality to integrate tProEcc device
 * into custom java based systems.
 * 
 * <p>
 * Class exposes three functions, which allows for:
 * </p>
 * <ul>
 * <li>validation of public key</li>
 * <li>digest calculation</li>
 * <li>verification of signature</li>
 * </ul>
 * <p>
 * Description, provided in this documentation mentions client side token API -
 * which is provided as a separate software package. Behaviour of token and the
 * token itself can be simulated and is available at <a href=
 * "https://tproecc-simulation-server.herokuapp.com">https://tproecc-simulation-server.herokuapp.com.
 * </a> Please consult all pieces of information provided on above site to
 * better understand, how to interact with tProEcc token.
 * </p>
 * 
 * <p>
 * Typical flow of information between tProEcc token, system to integrate and
 * SignatureVerifier class looks in following way (of course key generation is
 * typically done once, and then existing key is used in recurring signature
 * operations).
 * 
 * <p>
 * 1. tProEcc device generates key pair and returns json containing (tokenId,
 * curveType, publicKey, proofOfPossession).
 * </p>
 * <p>
 * 2. {@link #validatePublicKey} method is then used, to check correctness of
 * public key (please compare entry parameters and json fields)
 * </p>
 * <p>
 * 3. System which integrates token must store information, that validated
 * public key belongs to owner of the token (tokenId parameter can be used as
 * unique token identifier).
 * </p>
 * <p>
 * 4. Client side API call generates digest of provided message.
 * </p>
 * <p>
 * 5. tProEcc device signs digest, which results in json containing (tokenId,
 * digestType, curveType, signature).
 * </p>
 * <p>
 * 6. Hash of original message is generated <b>independently</b> at server side
 * using {@link #calculateDigest}.
 * </p>
 * <p>
 * 7. Signature of message is verifed using {@link #verifySignature}
 * 
 * @author Comarch Technologies
 * @version 0.9
 * @since 2017-05-16
 */

public class SignatureVerifier {

	/**
	 * Supported types of ECC curves enumeration.
	 */

	private static enum ECurveType {
		DSTU4145_233, DSTU4145_307, DSTU4145_431;
	}

	/**
	 * Supported types of hashing algorithms enumeration.
	 */

	private static enum EDigestType {
		KUPYNA_256, KUPYNA_384, KUPYNA_512, SHA_256, SHA_384, SHA_512;
	}

	/**
	 * Private constructor to avoid instantiation.
	 */

	private SignatureVerifier() {
	}

	/**
	 * Helper methods converts enum constants into string representing list of
	 * possible values.
	 * 
	 * @param states
	 *            all possible enum states -
	 *            <code>eg. ECurveType.values()</code>
	 * @return concatenated list of correct enum string literals
	 */

	private static <E extends Enum<E>> String getEnumConstants(E states[]) {
		String names = "";
		for (int i = 0; i < states.length; i++)
			names += "[" + states[i].name() + "]";
		return names;
	}

	/**
	 * Converts array of bytes into hexadecimal string
	 * 
	 * @param byteArray
	 *		array to be converted
	 *  
	 * @return hexadecimal representation of the array
	 */
	private static String byteArrToHex(byte[] byteArray) {
		char[] symbols = "0123456789abcdef".toCharArray();
		char[] hexValue = new char[byteArray.length * 2];

		for (int i = 0; i < byteArray.length; i++) {
			// convert the byte to an int
			int current = byteArray[i] & 0xff;
			// determine the Hex symbol for the last 4 bits
			hexValue[i * 2 + 1] = symbols[current & 0x0f];
			// determine the Hex symbol for the first 4 bits
			hexValue[i * 2] = symbols[current >> 4];
		}
		return new String(hexValue);
	}

	/**
	 * Converts curveType parameter into number of bits for particular curve.
	 * 
	 * @param curveType
	 *            - type of the curve
	 * @return number of bits
	 */

	private static int getCurveBits(final ECurveType curveType) {
		int curveBits;
		switch (curveType) {
		case DSTU4145_233:
			curveBits = 233;
			break;
		case DSTU4145_307:
			curveBits = 307;
			break;
		default:
			curveBits = 431;
			break;
		}
		return curveBits;
	}

	/**
	 * Calculate Kupyna type of the digest
	 * 
	 * @param document
	 *            document to be hashed.
	 * @param digestTypeEnum
	 *            type of kupyna hashing algorithm to be used
	 * @return hex representation of digest
	 * @throws SignatureVerifierIllegalArgumentException
	 *             on illegal arguments
	 */
	
	private static String calculateKupynaDigest(final byte[] document, final EDigestType digestTypeEnum)
			throws SignatureVerifierIllegalArgumentException {
		EKupynaType kupynaTypeEnum;

		switch (digestTypeEnum) {
		case KUPYNA_256:
			kupynaTypeEnum = EKupynaType.KUPYNA_256;
			break;
		case KUPYNA_384:
			kupynaTypeEnum = EKupynaType.KUPYNA_384;
			break;
		case KUPYNA_512:
		default:
			kupynaTypeEnum = EKupynaType.KUPYNA_512;
			break;
		}
		final Kupyna kupyna = new Kupyna(kupynaTypeEnum);
		kupyna.init();
		kupyna.update(document);
		return byteArrToHex(kupyna.digest());
	}

	/**
	 * Calculate SHA type of the digest
	 * 
	 * @param document
	 *            document to be hashed.
	 * @param digestTypeEnum
	 *            type of SHA hashing algorithm to be used
	 * @return hex digest
	 * @throws SignatureVerifierIllegalArgumentException
	 *             on illegal arguments
	 */

	private static String calculateShaDigest(final byte[] document, final EDigestType digestTypeEnum) {

		if (digestTypeEnum == EDigestType.SHA_256) {
			final SHA256Digest sha256 = new SHA256Digest();
			sha256.update(document, 0, document.length);
			final byte[] hash = new byte[sha256.getByteLength()];
			sha256.doFinal(hash, 0);
			return byteArrToHex(hash);
		}

		// SHA-384, SHA-512
		LongDigest digest;
		if (digestTypeEnum == EDigestType.SHA_384)
			digest = new SHA384Digest();
		else
			digest = new SHA512Digest();
		digest.update(document, 0, document.length);

		final byte[] hash = new byte[digest.getByteLength()];
		digest.doFinal(hash, 0);
		return byteArrToHex(hash);
	}

	/**
	 * Checks correctness of proof-of-possession string
	 * 
	 * @param popInput
	 *            string signed in pop (typically public key, might be
	 *            concatenated with token identifier)
	 * @param proofOfPossession
	 *            pop value to be verified
	 * @throws SignatureVerifierIllegalArgumentException
	 *             on incorrect argument
	 * @throws SignatureVerifierPOPException
	 *             on incorrect verification of pop
	 */

	private static void checkProofOfPossession(String popInput, String proofOfPossession)
			throws SignatureVerifierIllegalArgumentException, SignatureVerifierPOPException {
		String popInputDigest;
		Dstu4145Impl dstu = new Dstu4145Impl(431);
		ECPublicKeyParameters publicKey;
		try {
			popInputDigest = calculateKupynaDigest(popInput.getBytes("UTF-8"), EDigestType.KUPYNA_512);
			publicKey = PopPublic.getPopPublic();
			final BigInteger[] signatureRS = dstu.decodeSignature(proofOfPossession);
			boolean result = dstu.verifySignature(publicKey, popInputDigest, signatureRS[0], signatureRS[1]);
			if (!result)
				throw new SignatureVerifierPOPException("POP invalid signature");
		} catch (Dstu4145Exception e) {
			throw new SignatureVerifierPOPException(e);
		} catch (UnsupportedEncodingException e1) {
			throw new RuntimeException("no utf-8 encoding available");
		}
	}

	/**
	 * Validates correctness of provided public key. Structure of the key is
	 * expected to be hexadecimal number of length corresponding to parameter
	 * curveType. Public key is represented as uncompressed point (X,Y)
	 * coordinates over curve. Point coordinates must lie on the curve. Checks
	 * also guarantees, that provided public key was generated by tProEcc device
	 * by verifying proof of possession signature.
	 * 
	 * Function throws exception if any of above checks fail.
	 * 
	 * @param curveType
	 *            string representing type of the curve to be used for
	 *            validation of public key. Following values of this parameter
	 *            are valid: "DSTU_167", "DSTU_307", "DSTU_431"
	 * @param keyValue
	 *            public key value for curveType represented in hexadecimal form,
	 *            which starts with 04 - eg.
	 *            042f8e5575cf7807972a7345e0f27ba25d730603d49851634be506d2785fb384a3338f3bebf97cb2341833
	 * @param popInput
	 *            additional data used as one of the arguments to calculate
	 *            final proof of possesion value
	 * @param popResult
	 *            hexadecimal signature (proof of possesion) generated by token
	 *            (to confirm source of key generation)
	 * @exception SignatureVerifierException
	 *                on invalid structure of publicKeyHex
	 * @exception SignatureVerifierIllegalArgumentException
	 *                on invalid parameters
	 * @exception SignatureVerifierInvalidPublicKeyException
	 *                on invalid public key value (not point on curve)
	 * @exception SignatureVerifierPOPException
	 *                on invalid proof of possession signature
	 */

	public static void validatePublicKey(final String curveType, final String keyValue, final String popInput,
			final String popResult) throws SignatureVerifierException, SignatureVerifierIllegalArgumentException,
			SignatureVerifierInvalidPublicKeyException, SignatureVerifierPOPException {
		if (curveType == null)
			throw new SignatureVerifierIllegalArgumentException("curveName is null");
		if (keyValue == null)
			throw new SignatureVerifierIllegalArgumentException("publicKey is null");
		if (popInput == null)
			throw new SignatureVerifierIllegalArgumentException("popInput is null");
		if (popResult == null)
			throw new SignatureVerifierIllegalArgumentException("popResult is null");

		ECurveType curveTypeEnum = null;
		try {
			curveTypeEnum = ECurveType.valueOf(curveType);
		} catch (IllegalArgumentException exc) {
			throw new SignatureVerifierIllegalArgumentException(
					"Invalid curveName:" + curveType + " - expected:" + getEnumConstants(ECurveType.values()));
		}

		Dstu4145Impl dstu = new Dstu4145Impl(getCurveBits(curveTypeEnum));
		try {
			dstu.decodePublicKey(keyValue);
			// validate pop
			checkProofOfPossession(popInput, popResult);
		} catch (Dstu4145PointNotOnCurveException exc) {
			throw new SignatureVerifierInvalidPublicKeyException();
		} catch (Dstu4145Exception exc) {
			throw new SignatureVerifierException(exc);
		}
	}

	/**
	 * Calculates crypto digest of provided message. Various types of digests
	 * can be used - selection is done by parameter digestType. Message crypto
	 * digest (fingerprint, hash) is one way function, which takes arbitrary
	 * sized data and converts it into fixed-length hash.
	 * 
	 * 
	 * @param message
	 *            byte array containing message to be hashed
	 * @param digestType
	 *            type of the digest to be used - following values are accepted
	 *            "KUPYNA_256", "KUPYNA_384", "KUPYNA_512", "SHA_256",
	 *            "SHA_384", "SHA_512"
	 * @return hexadecimal representation of digest of message
	 * @exception SignatureVerifierIllegalArgumentException
	 *                on invalid parameters
	 */

	public static String calculateDigest(final byte[] message, final String digestType)
			throws SignatureVerifierIllegalArgumentException {
		if (message == null)
			throw new SignatureVerifierIllegalArgumentException("message is null");
		if (digestType == null)
			throw new SignatureVerifierIllegalArgumentException("digestType is null");

		EDigestType digestTypeEnum = null;
		try {
			digestTypeEnum = EDigestType.valueOf(digestType);
		} catch (IllegalArgumentException exc) {
			throw new SignatureVerifierIllegalArgumentException(
					"Invalid digestName - expected:" + getEnumConstants(EDigestType.values()));
		}

		if (digestTypeEnum == EDigestType.KUPYNA_256 || digestTypeEnum == EDigestType.KUPYNA_384
				|| digestTypeEnum == EDigestType.KUPYNA_512) {
			return calculateKupynaDigest(message, digestTypeEnum);
		}
		return calculateShaDigest(message, digestTypeEnum);
	}

	/**
	 * Verifies if provided digital signature of <code>digest</code> was
	 * generated by using private key corresponding to provided public key.
	 * Signature generation requires digest hash to be computed beforehand
	 * using @see #calculateDigest.
	 * 
	 * @param digest
	 *            hexadecimal fingerprint of the message which was signed
	 * @param curveType
	 *            string representing type of the curve to be used for
	 *            verification of the signature. Following values of this
	 *            parameter are valid: "DSTU_167", "DSTU_307", "DSTU_431"
	 * @param publicKey
	 *            public key for curveType represented in hexadecimal form,
	 *            which starts with 04 - eg.
	 *            042f8e5575cf7807972a7345e0f27ba25d730603d49851634be506d2785fb384a3338f3bebf97cb2341833
	 * @param signature
	 *            signature to be verified represented in hexadecimal form,
	 *            which start with 30 - eg.
	 * @return true - on positive verification, false - on negative verification
	 * @exception SignatureVerifierException
	 *                on invalid structure of publicKeyHex
	 * @exception SignatureVerifierIllegalArgumentException
	 *                on invalid parameters
	 * @exception SignatureVerifierInvalidPublicKeyException
	 *                on invalid public key value (not point on curve)
	 */

	public static boolean verifySignature(final String digest, final String curveType, final String publicKey,
			final String signature) throws SignatureVerifierException, SignatureVerifierInvalidPublicKeyException,
			SignatureVerifierIllegalArgumentException {
		if (digest == null)
			throw new SignatureVerifierIllegalArgumentException("digest is null");
		if (publicKey == null)
			throw new SignatureVerifierIllegalArgumentException("publicKey is null");
		if (signature == null)
			throw new SignatureVerifierIllegalArgumentException("signature is null");

		ECurveType curveTypeEnum = null;
		try {
			curveTypeEnum = ECurveType.valueOf(curveType);
		} catch (IllegalArgumentException exc) {
			throw new SignatureVerifierIllegalArgumentException(
					"Invalid curveName - expected:" + getEnumConstants(ECurveType.values()));
		}

		final Dstu4145Impl dstu = new Dstu4145Impl(getCurveBits(curveTypeEnum));
		boolean result = false;
		ECPublicKeyParameters publicKeyObj = null;
		try {
			publicKeyObj = dstu.decodePublicKey(publicKey);
		} catch (Dstu4145Exception e) {
			throw new SignatureVerifierInvalidPublicKeyException();
		}

		try {
			final BigInteger[] signatureRS = dstu.decodeSignature(signature);
			result = dstu.verifySignature(publicKeyObj, digest, signatureRS[0], signatureRS[1]);
		} catch (Dstu4145Exception e) {
			throw new SignatureVerifierException(e);
		}
		return result;
	}
}
