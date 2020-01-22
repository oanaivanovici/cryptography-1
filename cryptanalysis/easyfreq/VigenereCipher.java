package uk.ac.ncl.undergraduate.modules.csc3621.cryptanalysis.easyfreq;

/**
 * This class is capable of encrypt and decrypt according to the Vigen&egrave;re
 * cipher.
 *
 * @author Changyu Dong
 * @author Roberto Metere
 * @author Oana Ivanovici
 */
public class VigenereCipher {

	/**
	 * This variable denotes the total number of letters in the English alphabet
	 * and will be used in the modulus operation
	 */
	private static final int NUMBER_OF_LETTERS_IN_ALPHABET = 26;

	/**
	 * Encryption function of the Vigen&egrave;re cipher.
	 *
	 * <p>
	 * TODO: Complete the Vigen&egrave;re encryption function.
	 *
	 * @param plaintext
	 *            the plaintext to encrypt
	 * @param key
	 *            the encryption key
	 * @return the ciphertext according with the Vigen&egrave;re cipher.
	 */
	public static String encrypt(String plaintext, String key) {
		// Please, do not remove the editor-fold comments.
		// <editor-fold defaultstate="collapsed" desc="Write your code here
		// below!">

		String ciphertext = "";
		// index for ensuring the program iterates through the key to encrypt
		int indexOfKey = 0;

		for (int i = 0; i < plaintext.length(); i++) {
			char characterToEncrypt = plaintext.charAt(i);

			if (Util.isValidLetter(characterToEncrypt)) {
				// ensure the key iteration isn't at the end of the key. If it
				// is, key should start again from index 0
				if (indexOfKey >= key.length()) {
					indexOfKey = 0;
				}

				int indexOfCurrentLetterInAlphabet = Util.charToIndex(characterToEncrypt);
				int indexOfCurrentKeyLetterInAlphabet = Util.charToIndex(key.charAt(indexOfKey));
				// increment the index of the key to step through the chars of
				// the key
				indexOfKey += 1;

				// add the index of the letter in the alphabet to the index of
				// the i-th letter of the key, then mod 26
				char encryptedLetter = Util
						.indexToChar(Math.floorMod(indexOfCurrentLetterInAlphabet + indexOfCurrentKeyLetterInAlphabet,
								NUMBER_OF_LETTERS_IN_ALPHABET));

				ciphertext += encryptedLetter;
			} else { // maintain non-letter characters
				ciphertext += characterToEncrypt;
			}
		}

		return ciphertext;
		// </editor-fold> // END OF YOUR CODE
	}

	/**
	 * Decryption function of the Vigen&egrave;re cipher.
	 *
	 * <p>
	 * TODO: Complete the Vigen&egrave;re decryption function.
	 *
	 * @param ciphertext
	 *            the encrypted text
	 * @param key
	 *            the encryption key
	 * @return the plaintext according with the Vigen&egrave;re cipher.
	 */
	public static String decrypt(String ciphertext, String key) {
		// Please, do not remove the editor-fold comments.
		// <editor-fold defaultstate="collapsed" desc="Write your code here
		// below!">

		String plaintext = "";
		int indexOfKey = 0;

		for (int i = 0; i < ciphertext.length(); i++) {
			char characterToDecrypt = ciphertext.charAt(i);

			if (Util.isValidLetter(characterToDecrypt)) {
				// ensure the key iteration isn't at the end of the key. If it
				// is, key should start again from index 0
				if (indexOfKey >= key.length()) {
					indexOfKey = 0;
				}

				int indexOfCurrentLetterInAlphabet = Util.charToIndex(characterToDecrypt);
				int indexOfCurrentKeyLetterInAlphabet = Util.charToIndex(key.charAt(indexOfKey));
				// increment the index of the key to step through the chars of
				// the key
				indexOfKey += 1;

				// subtract the index of the i-th letter of the key from the
				// index of the letter in the alphabet to, then mod 26
				char decryptedLetter = Util
						.indexToChar(Math.floorMod(indexOfCurrentLetterInAlphabet - indexOfCurrentKeyLetterInAlphabet,
								NUMBER_OF_LETTERS_IN_ALPHABET));
				plaintext += decryptedLetter;
			} else {
				plaintext += characterToDecrypt;
			}
		}

		return plaintext;
		// </editor-fold> // END OF YOUR CODE
	}

}
