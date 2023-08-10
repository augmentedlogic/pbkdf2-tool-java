import com.augmentedlogic.pbkdf2tool.Pbkdf2Tool;

public class Tests
{

    public static void main(String[] args)
    {

        Pbkdf2Tool pb = new Pbkdf2Tool();

        try {
            pb.setDelimiter("$"); // this is optional
            pb.setEncoding(Pbkdf2Tool.BASE64);
            pb.setAlgo("PBKDF2WithHmacSHA256");

            String pass = pb.encode("mysecret", pb.genSalt(16), 20000);
            System.out.println(pass);

            System.out.println(pb.checkPassword("mysecret", pass));
            System.out.println(pb.checkPassword("wrongsecret", pass));

            pb.setEncoding(Pbkdf2Tool.RAW);
            String pass2 = pb.encodePasswordOnly("mysecret", pb.genSalt(16), 20000);
            System.out.println(pass2);

        } catch(Exception e) {
            System.out.println(e);
        }

    }

}
