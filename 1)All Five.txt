import java.util.*;

public class Ass_1{ 
public static void main(String[] args) { 
Scanner sc = new Scanner(System.in); 
System.out.println("===== Classical Encryption Techniques ====="); 
System.out.println("1. Caesar Cipher"); 
System.out.println("2. Monoalphabetic Cipher"); 
System.out.println("3. Polyalphabetic (Vigenère) Cipher"); 
System.out.println("4. Rail Fence Cipher"); 
System.out.println("5. Vernam Cipher"); 
System.out.print("Enter your choice (1-5): "); 
int choice = sc.nextInt(); 
sc.nextLine(); // consume newline 
System.out.print("Do you want to Encrypt (E) or Decrypt (D)? "); 
char action = sc.nextLine().toUpperCase().charAt(0); 
switch (choice) { 
// -------------------- 1. Caesar Cipher -------------------- 
case 1: 
System.out.print("Enter text: "); 
String text1 = sc.nextLine().toUpperCase(); 
System.out.print("Enter key (integer): "); 
int key = sc.nextInt(); 
StringBuilder caesarResult = new StringBuilder(); 
for (char c : text1.toCharArray()) { 
if (Character.isLetter(c)) { 
if (action == 'E') { 
caesarResult.append((char) ((c - 'A' + key) % 26 + 'A')); 
} else { 
caesarResult.append((char) ((c - 'A' - key + 26) % 26 + 'A')); 
} 
} else { 
caesarResult.append(c); 
} 
} 
System.out.println("Result: " + caesarResult); 
break; 
// -------------------- 2. Monoalphabetic Cipher -------------------- 
case 2: 
System.out.print("Enter text: "); 
String text2 = sc.nextLine().toUpperCase(); 
System.out.print("Enter 26-letter key (substitution alphabet): "); 
String key26 = sc.nextLine().toUpperCase(); 
if (key26.length() != 26) { 
System.out.println("Error: Key must have exactly 26 letters!"); 
break; 
} 
Map<Character, Character> mapping = new HashMap<>(); 
char ch = 'A'; 
for (int i = 0; i < 26; i++) { 
mapping.put(ch++, key26.charAt(i)); 
} 
StringBuilder monoResult = new StringBuilder(); 
if (action == 'E') { 
for (char c : text2.toCharArray()) monoResult.append(mapping.getOrDefault(c, c)); 
} else { 
Map<Character, Character> reverseMapping = new HashMap<>(); 
for (Map.Entry<Character, Character> entry : mapping.entrySet()) { 
reverseMapping.put(entry.getValue(), entry.getKey()); 
} 
for (char c : text2.toCharArray()) 
monoResult.append(reverseMapping.getOrDefault(c, c)); 
} 
System.out.println("Result: " + monoResult); 
break; 
// -------------------- 3. Polyalphabetic (Vigenère) Cipher -------------------- 
case 3: 
System.out.print("Enter text: "); 
String text3 = sc.nextLine().toUpperCase(); 
System.out.print("Enter key: "); 
String keyStr = sc.nextLine().toUpperCase(); 
StringBuilder polyResult = new StringBuilder(); 
int keyIndex = 0; 
for (char c : text3.toCharArray()) { 
if (Character.isLetter(c)) { 
int shift = keyStr.charAt(keyIndex) - 'A'; 
if (action == 'E') { 
polyResult.append((char) ((c - 'A' + shift) % 26 + 'A')); 
} else { 
polyResult.append((char) ((c - 'A' - shift + 26) % 26 + 'A')); 
} 
keyIndex = (keyIndex + 1) % keyStr.length(); 
} else { 
polyResult.append(c); 
} 
} 
System.out.println("Result: " + polyResult); 
break; 
// -------------------- 4. Rail Fence Cipher -------------------- 
case 4: 
System.out.print("Enter text: "); 
String text4 = sc.nextLine().replaceAll("\\s", ""); 
System.out.print("Enter number of rails: "); 
int rails = sc.nextInt(); 
if (action == 'E') { 
StringBuilder[] fence = new StringBuilder[rails]; 
for (int i = 0; i < rails; i++) fence[i] = new StringBuilder(); 
int rail = 0; 
int dir = 1; 
for (char c : text4.toCharArray()) { 
fence[rail].append(c); 
rail += dir; 
if (rail == 0 || rail == rails - 1) dir = -dir; 
} 
StringBuilder railResult = new StringBuilder(); 
for (StringBuilder sb : fence) railResult.append(sb); 
System.out.println("Result: " + railResult); 
} else { 
// Decryption 
char[] decrypted = new char[text4.length()]; 
int cycle = 2 * rails - 2; 
int index = 0; 
for (int r = 0; r < rails; r++) { 
int pos = r; 
boolean down = true; 
while (pos < text4.length()) { 
decrypted[pos] = text4.charAt(index++); 
if (r == 0 || r == rails - 1) { 
pos += cycle; 
} else { 
if (down) pos += 2 * (rails - r - 1); 
else pos += 2 * r; 
down = !down; 
} 
} 
} 
System.out.println("Result: " + new String(decrypted)); 
} 
break; 
// -------------------- 5. Vernam Cipher -------------------- 
case 5: 
System.out.print("Enter text: "); 
String text5 = sc.nextLine().toUpperCase(); 
System.out.print("Enter key (same length as text): "); 
String key5 = sc.nextLine().toUpperCase(); 
if (text5.length() != key5.length()) { 
System.out.println("Error: Key length must be same as text!"); 
break; 
} 
StringBuilder vernamResult = new StringBuilder(); 
for (int i = 0; i < text5.length(); i++) { 
char p = text5.charAt(i); 
char k = key5.charAt(i); 
if (Character.isLetter(p)) { 
char c = (char) (((p - 'A') ^ (k - 'A')) + 'A'); // encryption/decryption same 
vernamResult.append(c); 
} else { 
vernamResult.append(p); 
} 
} 
System.out.println("Result: " + vernamResult); 
break; 
default: 
System.out.println("Invalid choice!"); 
} 
sc.close(); 
} 
}