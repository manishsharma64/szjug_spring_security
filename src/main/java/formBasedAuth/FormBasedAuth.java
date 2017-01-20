package formBasedAuth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;

/**
 * Created by manishsharma on 12/22/16.
 */
@SpringBootApplication
public class FormBasedAuth {
    public static void main(String[] args) {
        SpringApplication.run(FormBasedAuth.class, args);
    }
}

@EnableWebSecurity
class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        System.out.println("SecurityConfig configure done");
        http
                .authorizeRequests()
                .antMatchers("/css/**", "/index").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/user/**").hasRole("USER")
                .antMatchers("/teacher/**").hasRole("TEACHER")
                .antMatchers("/").hasRole("TEACHER")
            .and()
                .csrf().disable().cors().disable()
                .addFilterBefore(csrfHeaderFilter(), CsrfFilter.class)
                .formLogin();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        System.out.println("SecurityConfig configureGlobal done");
        auth
                .inMemoryAuthentication()
                .withUser("admin").password("password").roles("ADMIN");
        auth
                .inMemoryAuthentication()
                .withUser("teacher").password("password").roles("TEACHER");
        auth
                .inMemoryAuthentication()
                .withUser("user").password("password1").roles("USER");


    }

    @Order(Ordered.HIGHEST_PRECEDENCE)
    private Filter csrfHeaderFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request,
                                            HttpServletResponse response, FilterChain filterChain)
                    throws ServletException, IOException {
                System.out.println("csrfHeaderFilter before " + request.getRequestURL());
                response.setHeader("Access-Control-Allow-Credentials","true");
                response.setHeader("Access-Control-Allow-Origin","http://localhost:63343");
                response.setHeader("Access-Control-Allow-Origin","*");
                response.setHeader("Access-Control-Allow-Methods", "POST, PUT, GET, OPTIONS, DELETE");
                response.setHeader("Access-Control-Allow-Headers", "Accept, x-requested-with, Authorization");
                response.setHeader("gogo","gogo");

                //Stop pre-flight request from getting authenticated.
                if(request.getHeader("Origin") == null) {
                    System.out.println("Origin is null");
                    if(request.getHeader("Access-Control-Request-Method") == null){
                        System.out.println("Access-Control-Request-Method is null");

                    }
                }
                filterChain.doFilter(request, response);

                response.setStatus(200);
                System.out.println(request.getAuthType());
                System.out.println(response.getStatus());

                System.out.println(response.getStatus());
                response.setHeader("Access-Control-Allow-Credentials","true");
                response.setHeader("Access-Control-Allow-Origin","http://localhost:63343");
                response.setHeader("hellohello","hellohello");
                System.out.println("csrfHeaderFilter after");
            }
        };
    }
}

@RestController("/")
class RestAPIs {

    @GetMapping(value = "admin/get",
            produces = MediaType.APPLICATION_JSON_VALUE)
    private String getAdmin(){
        System.out.println("FormBasedAuth getAdmin");
        return "{\"value\":\"admin\"}";
    }

    @GetMapping(value = "user/get",
            produces = MediaType.APPLICATION_JSON_VALUE)
    private String getUser(){
        System.out.println("FormBasedAuth getUser");
        return "{\"value\":\"user\"}";
    }

    @CrossOrigin
    @GetMapping(value = "user/gettwo",
            produces = MediaType.APPLICATION_JSON_VALUE)
    private String getUserTwo(){
        System.out.println("FormBasedAuth getUserTwo");
        return "{\"value\":\"user two\"}";
    }

    @GetMapping(value = "teacher/get",
            produces = MediaType.APPLICATION_JSON_VALUE)
    private String getTeacher(){
        return "{\"value\":\"teacher\"}";
    }

    @RequestMapping("user")
    private String user(Principal user) throws JsonProcessingException {
        String prettyUser = "<pre>" + new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(user) + "</pre>";
        return prettyUser;
    }

    @GetMapping(value = "other",
            produces = MediaType.APPLICATION_JSON_VALUE)
    private String getOther(){
        return "{\"value\":\"other\"}";
    }
}
