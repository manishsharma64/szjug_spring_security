import multiCustomAuth.CustomGrants;
import multiCustomAuth.CustomUser;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * Created by manishsharma on 1/19/17.
 */
public class CreateUsers {
    public static final String createUserSql = "insert into users (username, password, enabled) values (?,?,?)";
    public static final String createAuthoritySql = "insert into authorities (username, authority) values (?,?)";

    private static JdbcTemplate jdbcTemplate;
    private static BCryptPasswordEncoder bCryptPasswordEncoder;

    public static void main(String[] args) {
        jdbcTemplate =
                new JdbcTemplate(new DriverManagerDataSource("jdbc:oracle:thin:@localhost:1521:orcl", "hr", "oracle"));

        bCryptPasswordEncoder = new BCryptPasswordEncoder();

        CustomGrants adminGrants = new CustomGrants("ADMIN");
        CustomGrants userGrants = new CustomGrants("USER");
        CustomGrants teacherGrants = new CustomGrants("TEACHER");
        List<UserDetails> users = new ArrayList<>();

        users.add(new CustomUser("user", bCryptPasswordEncoder.encode("password"), true, Arrays.asList(userGrants)));
        users.add(new CustomUser("user1", bCryptPasswordEncoder.encode("password"), true, Arrays.asList(userGrants)));
        users.add(new CustomUser("user2", bCryptPasswordEncoder.encode("password"), true, Arrays.asList(userGrants)));
        users.add(new CustomUser("admin", bCryptPasswordEncoder.encode("password"), true, Arrays.asList(adminGrants)));
        users.add(new CustomUser("admin1", bCryptPasswordEncoder.encode("password"), true, Arrays.asList(adminGrants)));

        users.stream().forEach(user -> createUser(user));
    }


    private static void createUser(final UserDetails user) {
        jdbcTemplate.update(createUserSql, new PreparedStatementSetter() {
            public void setValues(PreparedStatement ps) throws SQLException {
                ps.setString(1, user.getUsername());
                ps.setString(2, user.getPassword());
                ps.setBoolean(3, user.isEnabled());
            }

        });
        insertUserAuthorities(user);
    }

    private static void insertUserAuthorities(UserDetails user) {
        for (GrantedAuthority auth : user.getAuthorities()) {
            jdbcTemplate.update(createAuthoritySql, user.getUsername(),
                    auth.getAuthority());
        }
    }
}
