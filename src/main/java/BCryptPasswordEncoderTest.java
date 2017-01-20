import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Created by manishsharma on 1/18/17.
 */
public class BCryptPasswordEncoderTest {
    public static void main(String[] args) {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

        String[] encodedPasswords = new String[10];
        for(int i=0; i<10; i++){
            encodedPasswords[i] = bCryptPasswordEncoder.encode("password");
            System.out.println(encodedPasswords[i]);
        }

        for(String password:encodedPasswords){
            System.out.println(bCryptPasswordEncoder.matches("password", password));
        }
    }
}
