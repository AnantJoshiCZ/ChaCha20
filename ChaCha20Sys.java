/**
 * @author Anant Joshi (mailto: anant.joshi@live.com)
 * @implNote this class creates an object which can be used to encrypt and decrypt messages using the ChaCha20 cryptographic algorithm.
 *  
 * There are 3 public methods in this class: encrypt(), decrypt() and generateKey() (details given within method javadoc comments)
 * 
 * Additional Notes: This implementation is based on the IETF standardized version of ChaCha20. It differs from the authors original 
 * implementation only slightly where it uses a 96-bit nonce vs 64-bit nonce given by the author. This also means the counter is only 32-bits
 * but this does not affect the implementation. Also, for the purposes of this implementation the nonce is input as a string of appropriate
 * size. It should be noted that the nonce must be unique for each message sent for the implementation to be secure.
 * 
 */
public class ChaCha20Sys {
	
	/**
	 * @param KEY_SIZE_BITS defines the size of the key
	 * @param NONCE_SIZE_BITS defines the size of the nonce 'number-used-once' (must be unique for each message) (based on IETF version)
	 * @param ROUNDS number of double-rounds (10 double-rounds = 20 quarter-rounds). Number less than 4 are NOT secure
	 * @param CONSTANT_WORD defines the constant word used in ChaCha initial state
	 */
	private int KEY_SIZE_BITS = 256;
	private int NONCE_SIZE_BITS = 96;
	private int ROUNDS = 10;
	private String CONSTANT_WORD = "expand 32-byte k";
	
	/**
	 * @param ChaChaState defines Word type array (size 16) which stores the key, nonce, constant and counter 
	 */
	private Word[] ChaChaState = new Word[16];
	
	/**
	 * 
	 * @param pass input password (or key)
	 * @param nonce input nonce (number-used-once)
	 * 
	 * @implNote the constructor creates an object which can be used to call encrypt()/decrypt() methods. The inputs are convetered to binary
	 * strings, and then adjusted to their respective standardized sizes. They are then converted to Word type arrays and stored in their 
	 * appropriate location (as given below) in the initial ChaCha state array. <br>
	 * 
	 * 				ChaChaState[0-3] = CONSTANT_WORD <br>
	 * 				ChaChaState[4-11] = KEY <br>
	 * 				ChaChaState[12] = COUNTER <br>
	 * 				ChaChaState[13-15] = NONCE <br>
	 */
	public ChaCha20Sys(String pass, String nonce) {
		String binStrPass = ConversionUtil.textToBinStr(pass);
		String adjustedBinStrPass = StringUtil.rightTruncRightPadWithZeros(binStrPass, KEY_SIZE_BITS);
		String binStrNonce = ConversionUtil.textToBinStr(nonce);
		String adjustedBinStrNonce = StringUtil.rightTruncRightPadWithZeros(binStrNonce, NONCE_SIZE_BITS);
		Word[] keyWordArr = ConversionUtil.binStrToWordArr(adjustedBinStrPass);
		Word[] constantWords = ConversionUtil.textToWordArr(CONSTANT_WORD);
		Word[] nonceWord = ConversionUtil.binStrToWordArr(adjustedBinStrNonce);
		this.ChaChaState[0] = constantWords[0];
		this.ChaChaState[1] = constantWords[1];
		this.ChaChaState[2] = constantWords[2];
		this.ChaChaState[3] = constantWords[3];
		
		//Setting key in ChaCha state - (word 4 to 11)
		for (int i = 4; i<=11; i++) {
			this.ChaChaState[i] = keyWordArr[i-4];
		}
		
		// Counter
		this.ChaChaState[12] = Word.ZERO();

		this.ChaChaState[13] = nonceWord[0];
		this.ChaChaState[14] = nonceWord[1];
		this.ChaChaState[15] = nonceWord[2];
		
	}
	
	/**
	 * 
	 * @param a Word type object
	 * @param b Word type object
	 * @param c Word type object
	 * @param d Word type object
	 * 
	 * @implNote this method is main source of randomness in this algorithm. It progressively adds, xors, and rotates (to the left) the input 
	 * Words a,b,c,d. This method follows the following order (note that all words are mutably updated): <br>
	 * 				
	 * 					a = a + b; d = d ^ a; d = d <<< 16;  <br>
	 * 					c = c + d; b = b ^ c; b = b <<< 12;  <br>
	 * 					a = a + b; d = d ^ a; d = d <<< 8;   <br>
	 * 					c = c + d; b = b ^ c; b = b <<< 7;   <br>
 	 *				  
	 */
	protected static void quarterRoundM(Word a, Word b, Word c, Word d) {
		a.addMod2p32M(b);  d.xorM(a);  d.rotateLeftM(16);
		c.addMod2p32M(d);  b.xorM(c);  b.rotateLeftM(12);
		a.addMod2p32M(b);  d.xorM(a);  d.rotateLeftM(8);
		c.addMod2p32M(d);  b.xorM(c);  b.rotateLeftM(7);
    }
	
	/**
	 * 
	 * @param chachaState initial ChaCha state
	 * @return chachaState
	 * 
	 * @implNote this method is used to create 512-bit blocks of the keystream. It primarily uses the quarter-round
	 * method to mix the initial state 20 times and then adds the initial state to the result. The is returned as
	 * 16 Words in a Word array.
	 */
	private Word[] generateKey(Word[] chachaState) {
		
		Word[] originalState = chachaState;
		// 10 loops × 2 rounds/loop = 20 rounds
		for (int i = 0; i < ROUNDS; i ++) {
			// Odd round
			quarterRoundM(chachaState[0], chachaState[4], chachaState[8], chachaState[12]); // column 0
			quarterRoundM(chachaState[1], chachaState[5], chachaState[9], chachaState[13]); // column 1
			quarterRoundM(chachaState[2], chachaState[6], chachaState[10], chachaState[14]); // column 2
			quarterRoundM(chachaState[3], chachaState[7], chachaState[11], chachaState[15]); // column 3
			// Even round
			quarterRoundM(chachaState[0], chachaState[5], chachaState[10], chachaState[15]); // diagonal 1 (main diagonal)
			quarterRoundM(chachaState[1], chachaState[6], chachaState[11], chachaState[12]); // diagonal 2
			quarterRoundM(chachaState[2], chachaState[7], chachaState[8], chachaState[13]); // diagonal 3
			quarterRoundM(chachaState[3], chachaState[4], chachaState[9], chachaState[14]); // diagonal 4
		}
		
		for (int i = 0; i < 16; i++) {
			chachaState[i].addMod2p32M(originalState[i]);
		}
		return chachaState;
	}
	
	/**
	 * @param plaintext input plaintext
	 * @return hexStrCipherText output ciphertext
	 * 
	 * @implNote this method it creates 512-bit blocks of the keystream and xor's 512 bits of the plaintext with it
	 * Finally, the xor'd ciphertext is returned
	 */
	public String encrypt(String plaintext) {
		Word[] plaintextWordArr = ConversionUtil.textToWordArr(plaintext);
		Word[] ciphertextWordArr = new Word[plaintextWordArr.length];
		
		for (int k=0; k<plaintextWordArr.length; k=k+16) {
			Word[] keyStateBlock = generateKey(ChaChaState);
			for (int i = 0; i < keyStateBlock.length && i+k < plaintextWordArr.length ; i++) {
				ciphertextWordArr[i+k] = plaintextWordArr[i+k].xor(keyStateBlock[i]);
			}
			ChaChaState[12] = ChaChaState[12].addMod2p32(Word.ONE());
		}
		String hexStrCipherText = ConversionUtil.wordArrToHexStr(ciphertextWordArr);
		return hexStrCipherText;
	}
	
	/**
	 * @param ciphertext input ciphertext
	 * @return hexStrCipherText output plaintext
	 * 
	 * @implNote this method it creates 512-bit blocks of the keystream and xor's 512 bits of the ciphertext with it
	 * Finally, the result plaintext is returned
	 */
	public String decrypt(String ciphertext) {
		Word[] ciphertextWordArr = ConversionUtil.hexStrToWordArr(ciphertext);
		Word[] plaintextWordArr = new Word[ciphertextWordArr.length];
		
		for (int k=0; k<ciphertextWordArr.length; k=k+16) {
			Word[] keyStateBlock = generateKey(ChaChaState);
			for (int i = 0; i < keyStateBlock.length && i+k < ciphertextWordArr.length ; i++) {
				plaintextWordArr[i+k] = ciphertextWordArr[i+k].xor(keyStateBlock[i]);
			}
			ChaChaState[12] = ChaChaState[12].addMod2p32(Word.ONE());
		}
		String plaintextStr = ConversionUtil.wordArrToText(plaintextWordArr);
		return plaintextStr.trim();
	}
}
