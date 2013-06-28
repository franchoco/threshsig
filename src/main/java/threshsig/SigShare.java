package threshsig;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;

/**
 * Signature Shares Class<BR>
 * Associates a signature share with an id & wraps a static verifier
 * 
 * Reference: "Practical Threshold Signatures",<br>
 * Victor Shoup (sho@zurich.ibm.com), IBM Research Paper RZ3121, 4/30/99<BR>
 * 
 * @author Steve Weis <sweis@mit.edu>
 */
public class SigShare {

  // Constants and variables
  //............................................................................
  private final static boolean CHECKVERIFIER = true;

  private int id;

  private BigInteger sig;

  private Verifier sigVerifier;

  // Constructors
  //............................................................................
  public SigShare(final int id, final BigInteger sig, final Verifier sigVerifier) {
    this.id = id;
    this.sig = sig;
    this.sigVerifier = sigVerifier;
  }

  public SigShare(final int id, final byte[] sig) {
    this.id = id;
    this.sig = new BigInteger(sig);
  }

  // Public Methods
  //............................................................................

  /**
   * Return this share's id. Needed for Lagrange interpolation
   * 
   * @return the id of this key share
   */
  public int getId() {
    return id;
  }

  /**
   * Return a BigInteger representation of this signature
   * 
   * @return a BigInteger representation of this signature
   */
  public BigInteger getSig() {
    return sig;
  }

  /**
   * Return this signature's verifier
   * 
   * @return A verifier for this signaute
   */
  public Verifier getSigVerifier() {
    return sigVerifier;
  }

  /**
   * Return a byte array representation of this signature
   * 
   * @return a byte array representation of this signature
   */
  public byte[] getBytes() {
    return sig.toByteArray();
  }

  @Override
  public String toString() {
    return "Sig[" + id + "]: " + sig.toString();
  }

  // Static methods
  //............................................................................
  // direct verification of shares, without transformation into RSA signature
  // (skips the EEA step)
  public static boolean verify(final byte[] data, final SigShare[] sigs, final int k, final int l,
      final BigInteger n, final BigInteger e) throws ThresholdSigException {
	  
    // Sanity Check - make sure there are at least k unique sigs out of l
    // possible
    validateSigs(sigs, k, l);
    BigInteger[] joined = joinsigs(data, sigs, k, l, n);
    if(joined==null) return false;
    
    // joined contains (eprime, w, x)
    final BigInteger xeprime = /*x*/joined[2].modPow(joined[0]/*eprime*/, n);
    final BigInteger we = /*w*/joined[1].modPow(e, n);
    return (xeprime.compareTo(we) == 0);
  }

// returns (eprime, w, x)
private static BigInteger[] joinsigs(final byte[] data, final SigShare[] sigs,
		final int k, final int l, final BigInteger n) {
	final BigInteger x = (new BigInteger(data)).mod(n);
    final BigInteger delta = SigShare.factorial(l);

    // Test the verifier of each signature to ensure there are
    // no dummy sigs thrown in to corrupt the batch
    if (CHECKVERIFIER) {
      final BigInteger FOUR = BigInteger.valueOf(4l);
      final BigInteger TWO = BigInteger.valueOf(2l);
      final BigInteger xtilde = x.modPow(FOUR.multiply(delta), n);

      try {
        final MessageDigest md = MessageDigest.getInstance("SHA");

        for (int i = 0; i < k; i++) {
          md.reset();
          final Verifier ver = sigs[i].getSigVerifier();
          final BigInteger v = ver.getGroupVerifier();
          final BigInteger vi = ver.getShareVerifier();

          // debug("v :" + v);
          md.update(v.toByteArray());

          // debug("xtilde :" + xtilde);
          md.update(xtilde.toByteArray());

          // debug("vi :" + vi);
          md.update(vi.toByteArray());

          final BigInteger xi = sigs[i].getSig();
          // debug("xi^2 :" + xi.modPow(TWO,n));
          md.update(xi.modPow(TWO, n).toByteArray());

          final BigInteger vz = v.modPow(ver.getZ(), n);

          final BigInteger vinegc = vi.modPow(ver.getC(), n).modInverse(n);
          // debug("v^z*v^-c :" + vz.multiply(vinegc).mod(n));
          md.update(vz.multiply(vinegc).mod(n).toByteArray());

          final BigInteger xtildez = xtilde.modPow(ver.getZ(), n);

          // TODO: CHECK PAPER!
          final BigInteger xineg2c = xi.modPow(ver.getC(), n).modInverse(n);
          // According to Shoup, pg. 8 this should be:
          // xi.modPow(TWO,n).modPow(ver.getC(),n).modInverse(n);

          // Something to do with working in Q_n since every
          // element is a square

          // debug("xi^-2cx: " + xineg2c.multiply(xtildez).mod(n));
          md.update(xineg2c.multiply(xtildez).mod(n).toByteArray());
          final BigInteger result = new BigInteger(md.digest()).mod(n);

          if (!result.equals(ver.getC())) {
            debug("Share verifier is not OK");
            return null;
          }
        }
      } catch (final java.security.NoSuchAlgorithmException ex) {
        debug("Provider could not locate SHA message digest .");
        ex.printStackTrace();
      }
    }
    // eprime = delta^2*4
    final BigInteger eprime = delta.multiply(delta).shiftLeft(2);

    BigInteger w = BigInteger.valueOf(1l);

    for (int i = 0; i < k; i++) {
      w = w.multiply(sigs[i].getSig().modPow(SigShare.lambda(sigs[i].getId(), sigs, delta), n));
    }
    w = w.mod(n);

    BigInteger[] joined = new BigInteger[3];
    joined[0] = eprime;
    joined[1] = w;
    joined[2] = x;
	return joined;
}

private static void validateSigs(final SigShare[] sigs, final int k, final int l) {
	final boolean[] haveSig = new boolean[l];
    for (int i = 0; i < k; i++) {
      // debug("Checking sig " + sigs[i].getId());
      if (sigs[i] == null) {
        throw new ThresholdSigException("Null signature");
      }
      if (haveSig[sigs[i].getId() - 1]) {
        throw new ThresholdSigException("Duplicate signature: " + sigs[i].getId());
      }
      haveSig[sigs[i].getId() - 1] = true;
    }
}

  /**
   * Returns the factorial of the given integer as a BigInteger
   * 
   * @return l!
   */
  private static BigInteger factorial(final int l) {
    BigInteger x = BigInteger.valueOf(1l);
    for (int i = 1; i <= l; i++) {
      x = x.multiply(BigInteger.valueOf(i));
    }

    return x;
  }

  /**
   * Compute lagarange interpolation points Reference: Shoup, pg 7.
   * 
   * @param ik - a point in S
   * @param S - a set of k points in {0...l}
   * @param delta - the factorial of the group size
   * 
   * @return the Lagarange interpolation of these points at 0
   */
  private static BigInteger lambda(final int ik, final SigShare[] S,
      final BigInteger delta) {
    // lambda(id,l) = PI {id!=j, 0<j<=l} (i-j')/(id-j')
    BigInteger value = delta;

    for (final SigShare element : S) {
      if (element.getId() != ik) {
        value = value.multiply(BigInteger.valueOf(element.getId()));
      }
    }

    for (final SigShare element : S) {
      if (element.getId() != ik) {
        value = value.divide(BigInteger.valueOf((element.getId() - ik)));
      }
    }

    return value;
  }
 
   private static int getByteLength(BigInteger b) {
       int n = b.bitLength();
       return (n + 7) >> 3;
   } 
  
  public static byte[] combine(final byte[] input, final SigShare[] sigs, final int k, final int l,
		  final RSAPublicKey pubk) {
	  BigInteger n = pubk.getModulus();
	  BigInteger e = pubk.getPublicExponent();
	  byte[] data = KeyShare.paddeddigest(input, n, "SHA1withRSA");
	  BigInteger[] joined = joinsigs(data, sigs, k, l, n);
	  if(joined==null) return null;
	
      // joined contains (eprime, w, x)
	  final BigInteger eprime = joined[0];
	  final BigInteger w = joined[1];
	  final BigInteger x = joined[2];
	  
      final BigInteger[] dab = extEuclid(eprime, e);
      BigInteger y = w.modPow(dab[1], n).multiply( x.modPow(dab[2],n) );
      y = y.mod(n);
      byte[] joinedSig = bigintToBytes(y, getByteLength(n));
      return joinedSig;
  }

  /**
   * Transform a BigInteger into a fixed-length byte array
   * @param i    BigInteger to transform
   * @param len  length of the byte array
   * @return byte array of length len representing value i
   */
  public static byte[] bigintToBytes(BigInteger i, int len) {
	  byte[] b = i.toByteArray();
	  // Easy case: already got the correct len
	  if(b.length == len) return b;
	  
	  // Strip leading 0x00 byte to get correct len
	  if(b.length == len+1 && b[0]==0) {
		  byte[] newb = new byte[len];
		  System.arraycopy(b, 1, newb, 0, len);
		  return b;
	  }
	  
	  // b is to short, add 0x00 bytes
	  if(b.length < len) {
		  byte[] newb = new byte[len];
		  System.arraycopy(b, 0, newb, len-b.length, b.length);
		  return newb;
	  }
	  
	  throw new RuntimeException("BigInteger larger than expected "+
	     len+" bytes");
  }
  
 
  /**
   * Execute the extended Euclidean algorithm to compute (d,a,b) with
   * the property that d = gcd(x,y) and x*a + y*b = d.
   * Return an array of 3 BigIntegers  (d,a,b)
   *
   * @param x
   * @param y
   * @return  (d,a,b) as an Array of three BigInteger
   */
  private static BigInteger[] extEuclid(BigInteger x, BigInteger y) {
  		BigInteger[] retval = new BigInteger[3];
  		if (y.equals(BigInteger.ZERO)) {
  			retval[0] = x;
  			retval[1] = BigInteger.ONE;
  			retval[2] = BigInteger.ZERO;
  			return retval;
  		}
  		retval = extEuclid(y, x.mod(y));
  		BigInteger a = retval[1];
  		BigInteger b = retval[2];
        retval[1] = b;
        retval[2] = a.subtract(b.multiply(x.divide(y)));
        return retval;
  }
  

  // Debugging
  //............................................................................
  private static void debug(final String s) {
    System.err.println("SigShare: " + s);
  }

}
