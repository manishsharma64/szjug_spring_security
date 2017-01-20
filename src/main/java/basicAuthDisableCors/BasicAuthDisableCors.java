package basicAuthDisableCors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Arrays;

/**
 * Created by manishsharma on 1/14/17.
 */
@SpringBootApplication
public class BasicAuthDisableCors {
    public static void main(String[] args) {
        SpringApplication.run(BasicAuthDisableCors.class);
    }
}

@EnableWebSecurity
class SecurityConfig extends WebSecurityConfigurerAdapter {

    CorsConfigurationSource corsConfigurationSource = new CorsConfigurationSource() {
        @Override
        public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
            CorsConfiguration corsConfiguration = new CorsConfiguration();

            corsConfiguration.addAllowedOrigin("http://localhost:63342");

            corsConfiguration.addAllowedHeader("Authorization");

            corsConfiguration.setAllowedMethods(Arrays.asList("POST", "GET"));

            corsConfiguration.setMaxAge(3600L);

            return corsConfiguration;
        }
    };

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        System.out.println("SecurityConfig configure done");
        http
                .httpBasic()
                .and()
                .authorizeRequests()
                .antMatchers("/css/**", "/index").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/student/**").hasRole("STUDENT")
                .antMatchers("/teacher/**").hasRole("TEACHER")
        .and().cors().configurationSource(corsConfigurationSource);
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
                .withUser("user").password("password2").roles("STUDENT");
    }
}


@RestController("/")
class RestAPIs {

    @GetMapping(value = "admin/get",
            produces = MediaType.APPLICATION_JSON_VALUE)
    private String getAdmin() {
        System.out.println("RestAPIs getAdmin");
        return "{\"value\":\"admin\"}";
    }

    @GetMapping(value = "student/get",
            produces = MediaType.APPLICATION_JSON_VALUE)
    private String getStudent() {
        System.out.println("RestAPIs getStudent");
        return "{\"value\":\"student\"}";
    }

    @GetMapping(value = "student/gettwo",
            produces = MediaType.APPLICATION_JSON_VALUE)
    private String getStudentTwo() {
        System.out.println("RestAPIs getStudentTwo");
        return "{\"value\":\"student two\"}";
    }

    @GetMapping(value = "teacher/get",
            produces = MediaType.APPLICATION_JSON_VALUE)
    private String getTeacher() {
        System.out.println("RestAPIs getTeacher");
        return "{\"value\":\"teacher\"}";
    }

    @RequestMapping("user")
    private String user(Principal user) throws JsonProcessingException {
        String prettyUser = "<pre>" + new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(user) + "</pre>";
        return prettyUser;
    }

    @GetMapping(value = "other",
            produces = MediaType.APPLICATION_JSON_VALUE)
    private String getOther() {
        return "{\"value\":\"other\"}";
    }
}