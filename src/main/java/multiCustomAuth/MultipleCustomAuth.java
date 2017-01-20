package multiCustomAuth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;

/**
 * Created by manishsharma on 12/24/16.
 */
@SpringBootApplication
public class MultipleCustomAuth {
    public static void main(String[] args) {
        SpringApplication.run(MultipleCustomAuth.class);
    }
}

@EnableWebSecurity
class WebSecurityConfig {

    @Configuration
    @Order(1)
    public static class ApiWebSecurityConfig extends WebSecurityConfigurerAdapter{

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .antMatcher("/api/**")
                    .authorizeRequests()
                    .anyRequest().hasAnyRole("ADMIN", "USER")
                .and()
                    .httpBasic()
                .and()
                    .authenticationProvider(new CustomBasicAuthenticationProvider());
        }
    }

    @Configuration
    @Order(2)
    public static class FormWebSecurityConfig extends WebSecurityConfigurerAdapter{

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests()
                    .antMatchers("/accesDenied.html").permitAll()
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .anyRequest().authenticated()
                .and()
                    .formLogin().and()
                    .userDetailsService(new CustomUserDetailsService())
                    .exceptionHandling().accessDeniedHandler(new CustomAccessDeniedHandler())
                .and()
                    .authenticationProvider(new CustomFormBasedAuthenticationProvider())
                    .authenticationProvider(new CustomFormBasedAuthenticationProviderTwo());
        }
    }
}

@RestController
class RestAPIs {

    @GetMapping("admin/get")
    private String getAdmin(){
        return "{\"value\":\"admin\"}";
    }

    @GetMapping("api/get")
    private String getApi(){
        return "{\"value\":\"user\"}";
    }

    @GetMapping("other")
    private String getOther(){
        return "{\"value\":\"other\"}";
    }

    @RequestMapping("user")
    private String user(Principal user) throws JsonProcessingException {
        String prettyUser = "<pre>" + new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(user) + "</pre>";
        return prettyUser;
    }
}

class CustomBasicAuthenticationProvider implements AuthenticationProvider {
    BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
    CustomUserDetailsService customUserDetailsService =
            new CustomUserDetailsService();

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String userName = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        CustomUser userDetails = customUserDetailsService.loadUserByUsername(userName);

        if(!bCryptPasswordEncoder.matches(password, userDetails.getPassword())){
            throw new BadCredentialsException("Username and password doesn't match");
        }

        return new UsernamePasswordAuthenticationToken(userDetails.getUsername(),
                userDetails.getPassword(),
                userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}

class CustomFormBasedAuthenticationProvider implements AuthenticationProvider {

    BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
    CustomUserDetailsService customUserDetailsService =
            new CustomUserDetailsService();

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String userName = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        CustomUser userDetails = customUserDetailsService.loadUserByUsername(userName);

        if(!bCryptPasswordEncoder.matches(password, userDetails.getPassword())){
            throw new BadCredentialsException("Username and password doesn't match");
        }

        return new UsernamePasswordAuthenticationToken(userDetails.getUsername(),
                userDetails.getPassword(),
                userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        if(authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class)){
            return false;
        }
        return false;
    }
}

class CustomFormBasedAuthenticationProviderTwo implements AuthenticationProvider {
    BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
    CustomUserDetailsService customUserDetailsService =
            new CustomUserDetailsService();

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String userName = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        CustomUser userDetails = customUserDetailsService.loadUserByUsername(userName);

        if(!bCryptPasswordEncoder.matches(password, userDetails.getPassword())){
            throw new BadCredentialsException("Username and password doesn't match");
        }

        return new UsernamePasswordAuthenticationToken(userDetails.getUsername(),
                userDetails.getPassword(),
                userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}

class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        String userName = (String) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        System.out.println("ALERT: " + userName + " is try to access restricted resource " + request.getServletPath());
        response.sendRedirect("http://localhost:8080/accesDenied.html");
    }
}