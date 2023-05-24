import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {

private BigInteger p;  // Első prím
private BigInteger q;  // Második prím
private BigInteger n;  // n = p * q
private BigInteger phi;  // phi(n) = (p - 1) * (q - 1)
private BigInteger e;  // Nyilvános kulcs
private BigInteger d;  // Privát kulcs

public RSA(int bitLength) {
        // P és Q generálása
        SecureRandom random = new SecureRandom();
        p = BigInteger.probablePrime(bitLength / 2, random);
        q = BigInteger.probablePrime(bitLength / 2, random);

        // N és phi(n) kiszámítása
        n = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Nyilvános és privát kulcsok generálása Euklideszi algoritmus segítségével
        e = generatePublicKey(phi);
        d = generatePrivateKey(e, phi);
        }

// Nyilvános kulcs generálása.
        /**
         * Ellenőrizzük az alábbi feltételeket a generált publicKey-re:
         * A publicKey-nek nagyobbnak kell lennie, mint 1 (publicKey.compareTo(BigInteger.ONE) <= 0), hogy ne legyen 1-nél vagy annál kisebb.
         * A publicKey-nek kisebbnek kell lennie, mint phi (publicKey.compareTo(phi) >= 0), hogy kisebb legyen a szorzatnál, amelyből phi kiszámítódott.
         * A publicKey-nek relatív prímnek kell lennie phi-val (!publicKey.gcd(phi).equals(BigInteger.ONE)), tehát nincs közös osztója a két számnak, kivéve az 1-et.
         *
         * A metódus lépéseivel tehát egy olyan nyilvános kulcsot generálunk, amely megfelel a RSA titkosítás követelményeinek,
         * vagyis nagyobb mint 1, kisebb mint phi, és relatív prím phi-val.
         * */
private BigInteger generatePublicKey(BigInteger phi) {
        BigInteger publicKey;
        do {
        publicKey = new BigInteger(phi.bitLength(), new SecureRandom());
        } while (publicKey.compareTo(BigInteger.ONE) <= 0 || publicKey.compareTo(phi) >= 0 || !publicKey.gcd(phi).equals(BigInteger.ONE));
        return publicKey;
        }

// Privát kulcs generálása
        /**
         * A modInverse metódus meghívása a publicKey objektumon a phi paraméterrel.
         * Ez a metódus a moduláris inverz számításáért felelős.
         * Azaz meghatározza azt a számot, amelyet a publicKey-nak szorozva modulo phi-val kapva az eredményt 1.
         * */
private BigInteger generatePrivateKey(BigInteger publicKey, BigInteger phi) {
        return publicKey.modInverse(phi);
        }

// Üzenet titkosítása
        /**
         * A message stringet byte tömbbé alakítjuk a getBytes() metódussal.
         * Ez a lépés az üzenetet átalakítja a hozzá tartozó bájtsorozattá.
         *
         * Létrehozunk egy BigInteger objektumot a byte tömb alapján a new BigInteger(messageBytes) konstruktorral.
         * Ez a m változóban tárolt üzenetet reprezentálja nagy egész számként.
         * A modPow(e, n) metódust használva a m-et a nyilvános kulcs (e) és a n modulózása segítségével titkosítjuk.
         * */
public BigInteger encrypt(String message) {
        byte[] messageBytes = message.getBytes();
        BigInteger m = new BigInteger(messageBytes);
        return m.modPow(e, n);
        }

// Titkosított üzenet visszafejtése
public String decrypt(BigInteger encryptedMessage) {
        // Az üzenet visszafejtése a titkosított üzenet és a privát kulcs hatványozása segítségével.
        BigInteger decryptedMessage = encryptedMessage.modPow(d, n);
        // A visszafejtett üzenet átalakítása byte tömbbé
        byte[] decryptedMessageBytes = decryptedMessage.toByteArray();
        // A byte tömb visszaalakítása String típussá
        return new String(decryptedMessageBytes);
        }

// Üzenet aláírása
public BigInteger sign(String message) {
        byte[] messageBytes = message.getBytes();
        BigInteger m = new BigInteger(messageBytes);
        // Az üzenet aláírása a privát kulccsal (d) és a modulussal (n) való hatványozással
        return m.modPow(d, n);
        }

// Aláírás ellenőrzése
        /**
         * Az aláírást visszafejtjük a nyilvános kulcs (e) és a modulus (n) felhasználásával.
         * A modPow() metódus alkalmazza a moduláris hatványozást, ami a visszafejtés lényeges része.
         * Összehasonlítjuk a visszafejtett aláírást (decryptedSignature) az eredeti üzenettel (m).
         */
public boolean verify(String message, BigInteger signature) {
        byte[] messageBytes = message.getBytes();
        BigInteger m = new BigInteger(messageBytes);

        BigInteger decryptedSignature = signature.modPow(e, n);
        return decryptedSignature.equals(m);
        }

public static void main(String[] args) {
        RSA rsa = new RSA(1024);
        String message = "message";

        BigInteger encryptedMessage = rsa.encrypt(message);
        String decryptedMessage = rsa.decrypt(encryptedMessage);
        BigInteger signature = rsa.sign("message");
        boolean isValidSignature = rsa.verify(message, signature);

        System.out.println("Original message: " + message);
        System.out.println("Encrypted message: " + encryptedMessage);
        System.out.println("Decrypted message: " + decryptedMessage);

        if (isValidSignature) {
        System.out.println("Az aláírás érvényes.");
        } else {
        System.out.println("Az aláírás érvénytelen.");
        }
        }
    }
