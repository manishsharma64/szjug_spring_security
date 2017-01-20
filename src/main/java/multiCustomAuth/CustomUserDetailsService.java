package multiCustomAuth;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collections;
import java.util.List;

/**
 * Created by manishsharma on 1/19/17.
 */
public class CustomUserDetailsService implements UserDetailsService {


    public static final String usersByUsernameQuery = "select username,password,enabled "
            + "from users " + "where username = ?";

    public static final String authoritiesByUsernameQuery = "select username,authority "
            + "from authorities " + "where username = ?";

    private static JdbcTemplate jdbcTemplate;

    {
        jdbcTemplate = new JdbcTemplate(new DriverManagerDataSource("jdbc:oracle:thin:@localhost:1521:orcl", "hr", "oracle"));
    }

    @Override
    public CustomUser loadUserByUsername(String username) throws UsernameNotFoundException {
        List<CustomUser> users = loadAllUsersByUsername(username);

        if(users.size() == 0){
            //Throw username not found exception.
        }
        List<CustomGrants> grants = loadUserAuthorities(username);
        return new CustomUser(users.get(0).getUsername(), users.get(0).getPassword(), users.get(0).isEnabled(), grants);
    }

    private List<CustomUser> loadAllUsersByUsername(String username) {
        return jdbcTemplate.query(this.usersByUsernameQuery,
                new String[] { username }, new RowMapper<CustomUser>() {
                    public CustomUser mapRow(ResultSet rs, int rowNum)
                            throws SQLException {
                        String username = rs.getString(1);
                        String password = rs.getString(2);
                        boolean enabled = rs.getBoolean(3);
                        return new CustomUser(username, password, enabled,
                                Collections.emptyList());
                    }
                });
    }

    private List<CustomGrants> loadUserAuthorities(String username) {
        return jdbcTemplate.query(this.authoritiesByUsernameQuery,
                new String[] { username }, new RowMapper<CustomGrants>() {
                    public CustomGrants mapRow(ResultSet rs, int rowNum)
                            throws SQLException {
                        String roleName = "ROLE_" + rs.getString(2);

                        return new CustomGrants(roleName);
                    }
                });
    }
}
