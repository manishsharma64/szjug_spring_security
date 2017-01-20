package multiCustomAuth;

import org.springframework.security.core.GrantedAuthority;

/**
 * Created by manishsharma on 1/19/17.
 */
public class CustomGrants implements GrantedAuthority {

    private String authority;

    public CustomGrants(String authority){
        this.authority = authority;
    }

    @Override
    public String getAuthority() {
        return authority;
    }
}
