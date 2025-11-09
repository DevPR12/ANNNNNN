import java.util.Scanner; 
public class ass_2{ 
// GCD function 
public static int gcd(int a, int b) { 
while (b != 0) { 
int temp = b; 
b = a % b; 
a = temp; 
} 
return a; 
} 
// Modular inverse function 
public static int modInverse(int e, int phi) { 
for (int i = 1; i < phi; i++) { 
if ((e * i) % phi == 1) { 
return i; 
} 
} 
return 0; 
} 
// Modular exponentiation 
public static int modExp(int base, int exp, int mod) { 
int result = 1; 
base = base % mod; 
while (exp > 0) { 
if (exp % 2 == 1) result = (result * base) % mod; 
exp = exp / 2; 
base = (base * base) % mod; 
} 
return result; 
} 
public static void main(String[] args) { 
Scanner sc = new Scanner(System.in); 
// Step 1: Take small primes 
System.out.print("Enter prime number p (>5): "); 
int p = sc.nextInt(); 
System.out.print("Enter prime number q (>5): "); 
int q = sc.nextInt(); 
int n = p * q; 
int phi = (p - 1) * (q - 1); 
System.out.println("n = " + n + ", phi = " + phi); 
// Step 2: Choose e 
int e; 
while (true) { 
System.out.print("Enter public key e (1<e<phi) coprime with phi: "); 
e = sc.nextInt(); 
if (gcd(e, phi) == 1) break; 
System.out.println("Invalid e! Try again."); 
} 
// Step 3: Compute d 
int d = modInverse(e, phi); 
System.out.println("Private key d = " + d); 
sc.nextLine(); // consume newline 
// Step 4: Take message 
System.out.print("Enter plaintext message (uppercase letters only): "); 
String message = sc.nextLine(); 
// Encryption 
int[] cipher = new int[message.length()]; 
System.out.print("Ciphertext: "); 
for (int i = 0; i < message.length(); i++) { 
int m = message.charAt(i) - 'A'; // map A-Z → 0-25 
cipher[i] = modExp(m, e, n); 
System.out.print(cipher[i] + " "); 
} 
System.out.println(); 
// Decryption 
System.out.print("Decrypted message: "); 
for (int i = 0; i < cipher.length; i++) { 
int m = modExp(cipher[i], d, n); // decrypted number 
System.out.print((char) (m + 'A')); // map 0-25 → A-Z 
} 
System.out.println(); 
} 
}