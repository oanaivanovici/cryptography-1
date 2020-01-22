package uk.ac.ncl.undergraduate.modules.csc3621.cryptanalysis.easyfreq;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Paths;

/**
 * This class is for frequency cryptanalysis of ciphertext when the key is an
 * integer.
 *
 * @author Changyu Dong
 * @author Roberto Metere
 * @author Oana Ivanovici
 */
public class FrequencyCryptanalysis {

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
	private int key;

	/**
	 * Frequency table (of the ciphertext).
	 */
	private FrequencyTable table;

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
	 * This variable is just to run the script interactive, that is with manual
	 * tunes.
	 */
	private boolean interactive = AUTOMATIC;

	/**
	 * This variable denotes the total number of letters in the English alphabet
	 * and will be used in the modulus operation
	 */
	private static final int NUMBER_OF_LETTERS_IN_ALPHABET = 26;

	/**
	 * Set the ciphertext to analyse.
	 *
	 * @param text
	 *            the text to set as ciphertext
	 */
	public void setCiphertext(String text) {
		this.ciphertext = text;
	}

	/**
	 * Create an new class to cryptanalyze texts.
	 */
	public FrequencyCryptanalysis() {
	}

	/**
	 * Constructor with interactive choice.
	 *
	 * @param interactive
	 *            whether it should ask for manual tuning or not
	 */
	public FrequencyCryptanalysis(boolean interactive) {
		this.interactive = interactive;
	}

	/**
	 * This method is to allow you to manually set the key can be used as a
	 * subroutine in your cryptanalysis for manual adjustment
	 */
	private void manualAdjustment() {
		int i;

		System.out.println("Enter the key (0-25): ");
		i = Util.reader.nextInt(); // Scans the next token of the input as an
									// int.
		if (i >= 0 && i <= 25) {
			this.key = i;
			System.out.println("The key is set to " + this.key);
		} else {
			System.out.println("The key is invalid (must be an integer between 0 and 25 included).");
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
	 * @return the key as the result of the cryptanalysis
	 */
	public int cryptanalysis() {
		// Please, do not remove the editor-fold comments.
		// <editor-fold defaultstate="collapsed" desc="Write your code here
		// below!">

		// Conduct frequency analysis of the ciphertext
		FrequencyAnalyser ciphertextFrequencyAnalyser = new FrequencyAnalyser();
		ciphertextFrequencyAnalyser.setText(ciphertext);
		FrequencyTable ciphertextFrequencyTable = ciphertextFrequencyAnalyser.analyse();

		// Get the index of the element with the highest frequency
		int largestFrequencyOfCiphertext = findHighestFrequency(ciphertextFrequencyTable);

		// ASSUME the letter with the highest frequency in the alphabet is E -
		// index 4
		int largestFrequencyOfPlaintext = 4;

		// Subtract the index of largestFrequencyOfPlaintext from the
		// largestFrequencyOfCiphertext to get the key
		this.key = largestFrequencyOfCiphertext - largestFrequencyOfPlaintext;

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

		return this.key;
	}

	/**
	 * This method is used for finding the index of the letter that has the
	 * higest frequency in the analysis
	 * 
	 * @param textFreqTbl
	 * @return index of the highest frequency letter
	 */
	private int findHighestFrequency(FrequencyTable textFreqTbl) {

		double[] freqTable = textFreqTbl.getTable();
		double highestFrequency = freqTable[0];
		int indexOfHighestFrequencyLetter = 0;

		for (int i = 1; i < freqTable.length; i++) {
			if (freqTable[i] > highestFrequency) {
				highestFrequency = freqTable[i];
				indexOfHighestFrequencyLetter = i;
			}
		}

		return indexOfHighestFrequencyLetter;
	}

	/**
	 * This method reconstructs the plaintext from the ciphertext with the key.
	 *
	 * <p>
	 * TODO:
	 * <ul>
	 * <li>After finding the key, use the key to decrypt the ciphertext
	 * <li>Store the plaintext in the class variable
	 * <code>this.plaintext</code>.
	 * </ul>
	 */
	public void decrypt() {
		// Please, do not remove the editor-fold comments.
		// <editor-fold defaultstate="collapsed" desc="Write your code here
		// below!">

		// initialise to an empty string to concatenate plaintext to it after
		// decryption
		plaintext = "";

		for (int i = 0; i < ciphertext.length(); i++) {

			char encryptedCharacter = ciphertext.charAt(i);

			if (Util.isValidLetter(encryptedCharacter)) {
				// floorMod calculates the floor modulus of the difference
				// between the encrypted letter
				// and the key with NUMBER_OF_LETTERS_IN_ALPHABET (26), which
				// gives the decrypted letter
				char decryptedLetter = Util.indexToChar(
						Math.floorMod(Util.charToIndex(encryptedCharacter) - this.key, NUMBER_OF_LETTERS_IN_ALPHABET));
				plaintext += decryptedLetter;
			} else { // maintain non-letters characters
				plaintext += encryptedCharacter;
			}
		}

		// </editor-fold> // END OF YOUR CODE
	}

	/**
	 * Show the results of the complete analysis.
	 */
	public void showResult() {
		System.out.println("The key is " + this.key);
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
		String mainPath, plaintextFilePath, ciphertextFilePath, plaintext, ciphertext;
		FrequencyAnalyser frequencyAnalyser;
		FrequencyTable frequencyTable;
		FrequencyCryptanalysis cryptanalysis;
		File solutionDirectory;
		String solutionFrequencyFilePath, solutionKeyFilePath, solutionPlaintextFilePath;

		// Add argument -i at run to enable interactive mode (and disable
		// automatic mode)
		if (0 < args.length && args[0].equals("-i")) {
			cryptanalysis = new FrequencyCryptanalysis(INTERACTIVE);
		} else {
			cryptanalysis = new FrequencyCryptanalysis(AUTOMATIC);
		}

		// Get resources
		mainPath = Paths.get(FrequencyCryptanalysis.class.getResource("/").toURI()).toString();
		plaintextFilePath = mainPath + "/res/pg1661.txt";
		ciphertextFilePath = mainPath + "/res/Exercise1Ciphertext.txt";
		solutionDirectory = new File(mainPath + "/solution1");
		solutionFrequencyFilePath = solutionDirectory + "/frequency.txt";
		solutionKeyFilePath = solutionDirectory + "/key.txt";
		solutionPlaintextFilePath = solutionDirectory + "/plaintext.txt";

		// Analyse the readable text
		plaintext = Util.readFileToBuffer(plaintextFilePath);
		frequencyAnalyser = new FrequencyAnalyser();
		frequencyAnalyser.setText(plaintext);
		frequencyTable = frequencyAnalyser.analyse();
		frequencyTable.print();

		// Crack the ciphertext
		ciphertext = Util.readFileToBuffer(ciphertextFilePath);
		cryptanalysis.setCiphertext(ciphertext);
		cryptanalysis.cryptanalysis();
		cryptanalysis.showResult();

		// Write solution in res path
		if (!solutionDirectory.exists()) {
			solutionDirectory.mkdir();
		}
		Util.printBufferToFile(frequencyTable.toString(), solutionFrequencyFilePath);
		Util.printBufferToFile(Integer.toString(cryptanalysis.key), solutionKeyFilePath);
		Util.printBufferToFile(cryptanalysis.plaintext, solutionPlaintextFilePath);
	}
}
