package threshsig;

import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;

import junit.framework.TestCase;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Random;

public class RSAThreshTest extends TestCase {
  private static final int KEYSIZE = 512;
  private static final int K = 6;
  private static final int L = 13;
  private static Dealer d;
  private static RSAPublicKey pubk;
  private static KeyShare[] keys;
  private static final byte[] data = new byte[1024];
  private static final SigShare[] sigs = new SigShare[K];

  @Override
  protected void setUp() throws InvalidKeyException {
	KeyShare[] newkeys;
    (new Random()).nextBytes(data);
    
    // Initialize a dealer with a keysize
    d = new Dealer(KEYSIZE);

    final long start = System.currentTimeMillis();
    long elapsed;
    // Generate a set of key shares
    d.generateKeys(K, L);

    elapsed = System.currentTimeMillis() - start;
    System.out.println("\tKey Gen total (ms): " + elapsed);

    // This is the group key common to all shares, which
    // is not assumed to be trusted. Treat like a Public Key
    pubk = d.getGroupKey().toPublicKey();

    // The Dealer has the shares and is assumed trusted
    // This should be destroyed, unless you want to reuse the
    // Special Primes of the group key to generate a new set of
    // shares
    newkeys = d.getShares();
    
    // externalize and retrieve key shares
    keys = new KeyShare[newkeys.length];
    for(int i=0; i<newkeys.length; i++) {
    		byte[] keydata = newkeys[i].wrap();
    		keys[i] = KeyShare.unwrap(keydata);
    }
  }

  public void testVerifySignatures() throws GeneralSecurityException {
    System.out.println("Attempting to verify a valid set of signatures...");
    // Pick a set of shares to attempt to verify
    // These are the indices of the shares
    final int[] S = { 3, 5, 1, 2, 10, 7 };

    for (int i = 0; i < S.length; i++)
      sigs[i] = keys[S[i]].rsasign(data);

    	byte[] signature = SigShare.combine(data, sigs, K, L, pubk);
    	
    	Signature s = Signature.getInstance("SHA1withRSA");
    s.initVerify(pubk);
    s.update(data);
    assertTrue( s.verify(signature) );
  }

  public void testVerifySignaturesAgain() throws GeneralSecurityException {
	  System.out.println("Attempting to verify a different set of shares...");

	  // Create k sigs to verify using different keys
	  final int[] T = { 8, 9, 7, 6, 1, 12 };
	  for (int i = 0; i < T.length; i++)
		  sigs[i] = keys[T[i]].rsasign(data);

	  byte[] signature = SigShare.combine(data, sigs, K, L, pubk);

      Signature s = Signature.getInstance("SHA1withRSA");
      s.initVerify(pubk);
      s.update(data);
      assertTrue( s.verify(signature) );
  }

  public void testVerifyBadSignature() throws GeneralSecurityException {
	  final int[] T = { 8, 9, 7, 6, 1, 12 };
	  for (int i = 0; i < T.length; i++)
		  sigs[i] = keys[T[i]].rsasign(data);
      sigs[3] = keys[3].rsasign("corrupt data".getBytes());
	  byte[] signature = SigShare.combine(data, sigs, K, L, pubk);	
	  
	  Signature s = Signature.getInstance("SHA1withRSA");
	  s.initVerify(pubk);
	  s.update(data);
	  assertFalse( signature!=null && s.verify(signature) );
  }
  
  public void testPerformance() throws NoSuchAlgorithmException {
    final int RUNS = 20;
    final int[] S = { 3, 5, 1, 2, 10, 7 };

    long start = System.currentTimeMillis(), elapsed;
    for (int i = 0; i < RUNS; i++)
      sigs[i % K] = keys[S[i % K]].rsasign(data);
    elapsed = System.currentTimeMillis() - start;
    System.out.println("Signing total (" + RUNS + " sigs) (ms): " + elapsed
        + " Average: " + (float) (elapsed / RUNS));

    for (int i = 0; i < K; i++)
      sigs[i] = keys[S[i]].rsasign(data);

    start = System.currentTimeMillis();
    for (int i = 0; i < RUNS; i++) {
  	  @SuppressWarnings("unused")
	  byte[] signature = SigShare.combine(data, sigs, K, L, pubk);
    }
    
    elapsed = System.currentTimeMillis() - start;
    System.out.println("Signature combination total (" + RUNS + " sigs) (ms): "
        + elapsed + " Average: " + (float) (elapsed / RUNS));
  }
}
