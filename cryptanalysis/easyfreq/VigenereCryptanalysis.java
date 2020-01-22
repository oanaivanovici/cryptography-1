package uk.ac.ncl.undergraduate.modules.csc3621.cryptanalysis.easyfreq;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URISyntaxException;
import java.nio.file.Paths;

/**
 * This class is for frequency cryptanalysis of ciphertext.
 *
 * @author Changyu Dong
 * @author Roberto Metere
 * @author Oana Ivanovici
 */
public class VigenereCryptanalysis {

	/**
	 * The ciphertext (encryption of the plaintext).
	 */
	private String ciphertext;

	/**
	 * The plaintext (readable content).
	 */
	private String plaintext;

	/**
	 * The key such that the encryption of the plaintext with such key gives the
	 * ciphertext.
	 */
	private final StringBuffer key = new StringBuffer();

	/**
	 * This variable is just to run the script interactive, that is with manual
	 * tunes.
	 */
	private boolean interactive;

	/**
	 * INTERACTIVE means that you can manually tune the analysis and/or the
	 * result.
	 */
	public static final boolean INTERACTIVE = true;

	/**
	 * AUTOMATIC means that the analysis will not ask any further information.
	 */
	public static final boolean AUTOMATIC = false;

	/**
	 * This variable denotes the total number of letters in the English alphabet
	 * and will be used in the modulus operation
	 */
	private static final int NUMBER_OF_LETTERS_IN_ALPHABET = 26;

	/**
	 * This variable denotes the inital assumed key length, 2, for the
	 * ciphertext encrypted with Vigenere cipher.
	 */

	private static final int INITIAL_ASSUMED_KEY_LENGTH = 2;

	/**
	 * This variable will ensure only 20 iterations of finding the key length
	 * will be done. Theoretically, we could check the length of the key equal
	 * up to the length of the ciphetext. However, computationally it is a
	 * lengthy process so we assume the key length will be within the range 1-20
	 */

	private static final int FINAL_ASSUMED_KEY_LENGTH = 20;

	/**
	 * The following two variables determine the upper and lower bounds of the
	 * indexes of coincidence. Usually, the index of coincidence is 0.067.
	 * However, these variable will allow some margin
	 */
	private static final double LOWER_BOUND_INDEX_OF_COINCIDENCE = 0.062;

	private static final double HIGHER_BOUND_INDEX_OF_COINCIDENCE = 0.072;

	/**
	 * The following variable is an array with the standard frequencies of the
	 * English letter alphabets which will be used in calculating the chi
	 * squared
	 */
	private static final double[] RESULTS_OF_FREQUENCY_ANALYSIS = { 8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015,
			6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978,
			2.360, 0.150, 1.974, 0.074 };

	/**
	 * Create an new class to cryptanalyze texts.
	 */
	public VigenereCryptanalysis() {
	}

	/**
	 * Constructor with interactive choice.
	 *
	 * @param interactive
	 *            whether it should ask for manual tuning or not
	 */
	public VigenereCryptanalysis(boolean interactive) {
		this.interactive = interactive;
	}

	/**
	 * Set the ciphertext to analyse.
	 *
	 * @param text
	 *            the text to set as
	 */
	public void setCiphertext(String text) {
		this.ciphertext = text;
	}

	/**
	 * This method is to allow you to manually set the key can be used as a
	 * subroutine in your cryptanalysis for manual adjustment
	 */
	private void manualAdjustment() {

		int answer;
		int index;
		char letter;

		do {
			System.out.println("How do you want to change the key (1: insert, 2:replace, 3:delete, 4:nothing)? ");
			answer = Util.reader.nextInt();
		} while (answer < 1 || answer > 4);

		switch (answer) {
		case 1:
			System.out.println("Enter the index where you want to insert the key charater");
			index = Util.reader.nextInt();
			System.out.println("Enter the letter you want to insert");
			letter = Util.reader.next().charAt(0);
			if (index < 0 || index > this.key.length()) {
				System.out.println("Index out of range");
			} else if (!Util.isValidLetter(letter)) {
				System.out.println("key character must be a letter");
			} else {
				this.key.insert(index, letter);

			}
			break;

		case 2:
			System.out.println("Enter the index of the character you want to replace");
			index = Util.reader.nextInt();
			System.out.println("Enter the new character");
			letter = Util.reader.next().charAt(0);
			if (index < 0 || index >= this.key.length()) {
				System.out.println("Index out of range");
			} else if (!Util.isValidLetter(letter)) {
				System.out.println("key character must be a letter");
			} else {
				this.key.replace(index, index, Character.toString(letter));
			}
			break;

		case 3:
			System.out.println("Enter the index of the character you want to delete");
			index = Util.reader.nextInt();
			if (index < 0 || index >= this.key.length()) {
				System.out.println("Index out of range");
			} else {

				this.key.deleteCharAt(index);

			}
			break;

		default:
			break;
		}
	}

	/**
	 * This method conducts cryptanalysis of the frequency of letters in the
	 * ciphertext to retrieve the encryption key.
	 *
	 * <p>
	 * TODO:
	 * <ul>
	 * <li>Conduct a frequency analysis of the internal buffer.
	 * <li>Find the key. You should try your best to find the key based on your
	 * analysis.
	 * <li>Store the key in the class variable <code>this.key</code>.
	 * </ul>
	 *
	 * <p>
	 * Manual adjustment in the method is allowed but needs to be justified in
	 * your report. You can create methods as you like.
	 *
	 * @return the key as result of the cryptanalysis
	 */
	public String cryptanalysis() {
		// Please, do not remove the editor-fold comments.
		// <editor-fold defaultstate="collapsed" desc="Write your code here
		// below!">

		int potentialKeyLength = 0;
		String[] shiftCiphers = null;
		double[] expectedCountOfEachLetter = calculateExpectedCountOfLetter(RESULTS_OF_FREQUENCY_ANALYSIS,
				ciphertext.length());
		double[] chiSquaredForAllKeys = new double[NUMBER_OF_LETTERS_IN_ALPHABET];

		// Find the key length by iteratively going through each potential key
		// length up to the final assumed one. For each keylength:
		// - get all the letters from ciphertext which are encrypted with the
		// same letter of the key.
		// - calculate index of coincidence of each element in lettersEncrypted.
		// - average out the indexes, if the average index of coincidence
		// calculated is around the 0.067 margin, we can consider we found a
		// potential key length. If that's not the case, increase the key length
		// When potential key length is found, the segments of the ciphertext
		// split given the index of the encryption key which they are encrypted
		// with will yield a number of shift ciphers
		for (int h = INITIAL_ASSUMED_KEY_LENGTH; h < FINAL_ASSUMED_KEY_LENGTH; h++) {
			String[] lettersEncrypted = getLettersEncryptedWithSameKey(h);
			double[] indexesOfCoincidence = calculateIndexOfCoincidence(h, lettersEncrypted);
			double averageOfIndexOfCoincidence = calculateAverageIndexOfCoincidence(indexesOfCoincidence);

			if (averageOfIndexOfCoincidence > LOWER_BOUND_INDEX_OF_COINCIDENCE
					&& averageOfIndexOfCoincidence < HIGHER_BOUND_INDEX_OF_COINCIDENCE) {
				potentialKeyLength = h;
				shiftCiphers = lettersEncrypted;
				break;
			}
		}

		// Decrypt each shift cipher with every possible key (0-25).
		// Calculate the chi squared for each plaintext, then store it
		// to find the minimum chiSquared.
		// The character with the smallest chi squared is the key for this
		// segment of the cipher.
		// the final key is then all the characters with the smallest chi
		// squared's concatenated
		for (int i = 0; i < shiftCiphers.length; i++) {
			for (int j = 0; j < NUMBER_OF_LETTERS_IN_ALPHABET; j++) {
				String plaintext = decryptShiftCiphers(shiftCiphers[i], j);
				chiSquaredForAllKeys[j] = calculateChiSquared(plaintext, expectedCountOfEachLetter);
			}
			int keyForCurrentCipher = findLowestChiSquared(chiSquaredForAllKeys);
			this.key.append(Util.indexToChar(keyForCurrentCipher));
		}

		// </editor-fold> // END OF YOUR CODE
		// The following code allows you to manually adjust your result.
		if (this.interactive) {
			String answer;
			do {

				do {
					System.out.println("Do you want to see the plaintext (Y/N)? ");
					answer = Util.reader.next().toUpperCase();
				} while (!(answer.equals("Y") || answer.equals("N")));

				if (answer.equals("Y")) {
					this.decrypt();
					System.out.println(this.plaintext);
				}

				do {
					System.out.println("Do you want to see the key (Y/N)? ");
					answer = Util.reader.next().toUpperCase();
				} while (!(answer.equals("Y") || answer.equals("N")));

				if (answer.equals("Y")) {
					System.out.println(this.key);
				}

				do {
					System.out.println("Do you want to change the key (Y/N)? ");
					answer = Util.reader.next().toUpperCase();
				} while (!(answer.equals("Y") || answer.equals("N")));

				if (answer.equals("Y")) {
					this.manualAdjustment();
				}

				do {
					System.out.println("Do you want to stop (Y/N)? ");
					answer = Util.reader.next().toUpperCase();
				} while (!(answer.equals("Y") || answer.equals("N")));

			} while (!answer.equals("Y"));
		}

		return this.key.toString();
	}

	/**
	 * This method splits the ciphertext into an array of size of the assumed
	 * key length, which when the key length is found, will return shift ciphers
	 * to decrypt
	 * 
	 * @param assumedKeyLength
	 * @return array of letters encrypted with the same index of the key
	 */
	private String[] getLettersEncryptedWithSameKey(int assumedKeyLength) {
		String[] lettersEncrypted = new String[assumedKeyLength];
		for (int i = 0; i < ciphertext.length(); i++) {
			int position = i % assumedKeyLength;
			if (i < assumedKeyLength) {
				lettersEncrypted[position] = "";
			}
			lettersEncrypted[position] += (ciphertext.charAt(i));
		}
		return lettersEncrypted;
	}

	/**
	 * This method calculates the indexes of coincidence for each shift cipher
	 * obtained from segmenting the ciphertext. The calculation excludes
	 * occurrences of 0 as they would not affect the sumOfOccurrences
	 * 
	 * @param assumedKeyLength
	 * @param lettersEncrypted
	 * @return array with indexes of coincidence
	 */
	private double[] calculateIndexOfCoincidence(int assumedKeyLength, String[] lettersEncrypted) {
		double[] indexesOfCoincidence = new double[assumedKeyLength];
		for (int j = 0; j < lettersEncrypted.length; j++) {
			double sumOfOccurrences = 0.0;
			int[] numberOfOccurrences = FrequencyAnalyser.countOccurrencesOfLetter(lettersEncrypted[j]);
			for (int k = 0; k < NUMBER_OF_LETTERS_IN_ALPHABET; k++) {
				double occurrenceOfLetter = numberOfOccurrences[k];
				if (occurrenceOfLetter > 0.0) {
					sumOfOccurrences += (occurrenceOfLetter * (occurrenceOfLetter - 1.0))
							/ (double) (lettersEncrypted[j].length() * (lettersEncrypted[j].length() - 1.0));
				}
			}
			indexesOfCoincidence[j] = sumOfOccurrences;
		}
		return indexesOfCoincidence;
	}

	/**
	 * This method averages out the indexes of coincidence in order to decide
	 * the final value of it which will be used in assessing whether it is
	 * within the boundaries LOWER_BOUND_INDEX_OF_COINCIDENCE and
	 * HIGHER_BOUND_INDEX_OF_COINCIDENCE. If it is, it means we found the key
	 * length.
	 * 
	 * @param indexesOfCoincidence
	 * @return the average of the indexes of coincidence
	 */
	private double calculateAverageIndexOfCoincidence(double[] indexesOfCoincidence) {
		double sumOfCoincidences = 0.0;
		for (int k = 0; k < indexesOfCoincidence.length; k++) {
			sumOfCoincidences += indexesOfCoincidence[k];
		}
		return sumOfCoincidences / indexesOfCoincidence.length;
	}

	/**
	 * In order to calculate the chi squared value to solve each shift cipher,
	 * we need to calculate how many times we expect a letter to occur in a
	 * given text of length x, given the known frequency analysis of the letters
	 * 
	 * @param resultsOfFreqAnalysis
	 * @param lengthOfText
	 * @return array with expected counts of each letter in a text of given
	 *         length x
	 */
	private static double[] calculateExpectedCountOfLetter(double[] resultsOfFreqAnalysis, int lengthOfText) {
		double[] expectedCounts = new double[NUMBER_OF_LETTERS_IN_ALPHABET];
		for (int i = 0; i < NUMBER_OF_LETTERS_IN_ALPHABET; i++) {
			expectedCounts[i] = (lengthOfText * resultsOfFreqAnalysis[i]) / 100;
		}
		return expectedCounts;
	}

	/**
	 * This method decrypts the shift ciphers that resulted from the splitting
	 * of the ciphertext based on key length. It is used in trialing each key
	 * from 0-25 to decrypt a ciphertext, which will then be used for
	 * calculating chi squared
	 * 
	 * @param ciphertext
	 * @param key
	 * @return string with the segment of the ciphertext (shift cipher)
	 *         decrypted
	 */
	private static String decryptShiftCiphers(String ciphertext, int key) {
		StringBuilder plaintext = new StringBuilder();
		for (int i = 0; i < ciphertext.length(); i++) {
			char letter = ciphertext.charAt(i);
			if (Util.isValidLetter(letter)) {
				char decryptedLetter = Util
						.indexToChar(Math.floorMod(Util.charToIndex(letter) - key, NUMBER_OF_LETTERS_IN_ALPHABET));
				plaintext.append(decryptedLetter);
			}
		}
		return plaintext.toString();
	}

	/**
	 * This method returns the chi squared for all letters for a certain
	 * plaintext. chiSquared = sum (Count i - Expected i)^2/Expected i
	 * 
	 * @param text
	 * @param expectedCountOfEachLetter
	 * @return the chi squared of all the letters
	 */
	private static double calculateChiSquared(String text, double[] expectedCountOfEachLetter) {
		int[] occurrencesOfEachLetter = FrequencyAnalyser.countOccurrencesOfLetter(text);
		double chiSquared = 0.0;
		for (int i = 0; i < NUMBER_OF_LETTERS_IN_ALPHABET; i++) {
			chiSquared += ((Math.pow(occurrencesOfEachLetter[i] - expectedCountOfEachLetter[i], 2))
					/ (double) expectedCountOfEachLetter[i]);
		}
		return chiSquared;
	}

	/**
	 * This method returns the lowest Chi Squared from all the chi squared's for
	 * all keys. The lowest chi squared denotes the key for the shift cipher
	 * 
	 * @param chiSquaredForAllKeys
	 * @return index of the character with the lowest chi square, which will
	 *         denote the key
	 */
	private static int findLowestChiSquared(double[] chiSquaredForAllKeys) {
		double lowestChiSquared = Integer.MAX_VALUE;
		int indexOfLowestChiSquared = 0;

		for (int i = 0; i < chiSquaredForAllKeys.length; i++) {
			if (chiSquaredForAllKeys[i] < lowestChiSquared && chiSquaredForAllKeys[i] != 0.0) {
				lowestChiSquared = chiSquaredForAllKeys[i];
				indexOfLowestChiSquared = i;
			}
		}
		return indexOfLowestChiSquared;
	}

	/**
	 * This method reconstructs the plaintext from the ciphertext with the key.
	 */
	public void decrypt() {
		this.plaintext = VigenereCipher.decrypt(this.ciphertext, this.key.toString());
	}

	/**
	 * Show the results of the complete analysis.
	 */
	public void showResult() {
		System.out.println("The key is " + this.key.toString());
		this.decrypt();
		System.out.println("The plaintext is:");
		System.out.println(this.plaintext);
	}

	/**
	 * @param args
	 *            the command line arguments
	 * @throws java.io.IOException
	 *             errors reading from files
	 * @throws java.net.URISyntaxException
	 *             Errors in retrieving resources
	 */
	public static void main(String[] args) throws IOException, URISyntaxException {
		String mainPath, ciphertextFilePath, ciphertext;
		VigenereCryptanalysis cryptanalysis;
		File solutionDirectory;
		String solutionKeyFilePath, solutionPlaintextFilePath;

		// Add argument -i at run to enable interactive mode (and disable
		// automatic mode)
		if (0 < args.length && args[0].equals("-i")) {
			cryptanalysis = new VigenereCryptanalysis(INTERACTIVE);
		} else {
			cryptanalysis = new VigenereCryptanalysis(AUTOMATIC);
		}

		// Get resources
		mainPath = Paths.get(FrequencyCryptanalysis.class.getResource("/").toURI()).toString();
		ciphertextFilePath = mainPath + "/res/Exercise2Ciphertext.txt";
		solutionDirectory = new File(mainPath + "/solution2");
		solutionKeyFilePath = solutionDirectory + "/key.txt";
		solutionPlaintextFilePath = solutionDirectory + "/plaintext.txt";

		// Do the job
		ciphertext = Util.readFileToBuffer(ciphertextFilePath);
		cryptanalysis.setCiphertext(ciphertext);
		cryptanalysis.cryptanalysis();
		cryptanalysis.showResult();

		// Write solution in res path
		if (!solutionDirectory.exists()) {
			solutionDirectory.mkdir();
		}
		Util.printBufferToFile(cryptanalysis.key.toString(), solutionKeyFilePath);
		Util.printBufferToFile(cryptanalysis.plaintext, solutionPlaintextFilePath);
	}
}
