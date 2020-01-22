package uk.ac.ncl.undergraduate.modules.csc3621.cryptanalysis.easyfreq;

import java.util.Arrays;

/**
 * This class is to compute a frequency table of a texts.
 *
 * @author Changyu Dong
 * @author Roberto Metere
 * @author Oana Ivanovici
 */
public class FrequencyAnalyser {

	/**
	 * The text to analyse
	 */
	private String text;

	/**
	 * This variable denotes the total number of letters in the English alphabet
	 * and will be used in the modulus operation
	 */
	private static final int NUMBER_OF_LETTERS_IN_ALPHABET = 26;

	/**
	 * Get the text to analyse.
	 *
	 * @return the text to analyse.
	 */
	public String getText() {
		return text;
	}

	/**
	 * Set the text to analyse.
	 *
	 * @param text
	 *            the text to analyse.
	 */
	public void setText(String text) {
		this.text = text;
	}

	/**
	 * This method returns a frequency table as a result of the analysis of the
	 * text.
	 *
	 * TODO: complete the function that conduct a frequency analysis of the
	 * internal buffer and produce a frequency table based on the analysis.
	 * Please, write your code between the comments as appropriate.
	 *
	 * @return frequency table as a result of the analysis of the text
	 */
	public FrequencyTable analyse() {
		// Please, do not remove the editor-fold comments.
		// <editor-fold defaultstate="collapsed" desc="Write your code here
		// below!">

		// Count the number of occurrences of each letter, put them into array
		// numberOfOccurrencesOfEachLetter.
		// Count the total number of valid letters
		FrequencyTable frequencyTable = new FrequencyTable();
		int totalNumberOfValidLetters = 0;
		int[] numberOfOccurrencesOfEachLetter = countOccurrencesOfLetter(text);

		for (int i = 0; i < text.length(); i++) {
			if (Util.isValidLetter(text.charAt(i))) {
				totalNumberOfValidLetters += 1;
			}
		}

		// Divide the number of occurrences of the letter by the total number of
		// valid letters in the text.
		// Set the frequency of each letter
		for (int i = 0; i < numberOfOccurrencesOfEachLetter.length; i++) {
			double newFrequencyOfLetter = numberOfOccurrencesOfEachLetter[i] / (double) totalNumberOfValidLetters;
			frequencyTable.setFrequency(Util.indexToChar(i), newFrequencyOfLetter);
		}

		return frequencyTable;

		// </editor-fold> // END OF YOUR CODE
	}

	/**
	 * This method counts the occurrences of each letter in a given text. It is
	 * used for calculating the frequency analysis, as well as for invoking in
	 * the calculation of index of coincidence in the cryptanalysis of the
	 * Vigenere cipher
	 * 
	 * @param text
	 * @return array of ints outlining the number of occurrences of each letter
	 */
	public static int[] countOccurrencesOfLetter(String text) {
		int[] numberOfOccurrencesOfEachLetter = new int[NUMBER_OF_LETTERS_IN_ALPHABET];

		for (int i = 0; i < text.length(); i++) {
			char letter = text.charAt(i);

			if (Util.isValidLetter(letter)) {
				int indexOfCurrentLetter = Util.charToIndex(letter);
				numberOfOccurrencesOfEachLetter[indexOfCurrentLetter] += 1;
			}
		}

		return numberOfOccurrencesOfEachLetter;
	}

}
