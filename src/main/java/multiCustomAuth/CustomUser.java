package multiCustomAuth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * Created by manishsharma on 1/19/17.
 */
public class CustomUser implements UserDetails {
    private final String userName;
    private final String password;
    private final boolean isEnabled;
    private final List<CustomGrants> customGrantss;

    public CustomUser(String user, String password, boolean b, List<CustomGrants> customGrantss) {
        this.userName = user;
        this.password = password;
        this.isEnabled = b;
        this.customGrantss = customGrantss;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return customGrantss;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return userName;
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return isEnabled;
    }
}
