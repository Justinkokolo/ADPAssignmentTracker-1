package org.assignmentTracker.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private static final String USER_ROLE = "USER";
    private static final String ADMIN_ROLE = "ADMIN";

    private static final String[] AUTH_LIST = { //
            "/v2/api-docs", //
            "/configuration/ui", //
            "/swagger-resources", //
            "/configuration/security", //
            "/swagger-ui.html", //
            "/webjars/**" //
    };

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("Justin")
                .password(encoder().encode("password"))
                .roles(ADMIN_ROLE, USER_ROLE)
                .and()
                .withUser("Robyn")
                .password(encoder().encode("wordpass"))
                .roles(USER_ROLE);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests().antMatchers(AUTH_LIST).authenticated().and().httpBasic();
        http.httpBasic()
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.GET, "/assignment/all").hasRole(USER_ROLE)
                .antMatchers(HttpMethod.GET, "/assignment/all/date").hasRole(USER_ROLE)
                .antMatchers(HttpMethod.GET, "/assignment/all/name").hasRole(USER_ROLE)
                .antMatchers(HttpMethod.GET, "/assignment/all/subject").hasRole(USER_ROLE)
                .antMatchers(HttpMethod.POST, "/assignment/create").hasRole(USER_ROLE)
                .antMatchers(HttpMethod.GET, "/assignment/read/**").hasRole(USER_ROLE)
                .antMatchers(HttpMethod.PUT, "/assignment/update").hasRole(USER_ROLE)
                .antMatchers(HttpMethod.DELETE, "/assignment/delete/**").hasRole(USER_ROLE)

                .antMatchers(HttpMethod.GET, "/vote/all").hasRole(USER_ROLE)
                .antMatchers(HttpMethod.GET, "/vote/all/username").hasRole(USER_ROLE)
                .antMatchers(HttpMethod.POST, "/vote/create").hasRole(USER_ROLE)
                .antMatchers(HttpMethod.GET, "/vote/read/**").hasRole(USER_ROLE)
                .antMatchers(HttpMethod.PUT, "/vote/update").hasRole(USER_ROLE)
                .antMatchers(HttpMethod.DELETE, "/vote/delete/**").hasRole(USER_ROLE)

                .antMatchers(HttpMethod.POST, "/assignmenttrackerdb/**/create", "/assignmenttrackerdb/**/delete/**").hasRole(ADMIN_ROLE)
                .antMatchers(HttpMethod.GET, "/assignmenttrackerdb/**/read/**", "/assignmenttrackerdb/**/all").hasRole(USER_ROLE)
                .antMatchers(HttpMethod.POST, "/lecture/**").hasRole(ADMIN_ROLE)
                .antMatchers(HttpMethod.DELETE, "/lecture/delete/**").hasRole(ADMIN_ROLE)
                .antMatchers(HttpMethod.GET, "/lecture/read/**", "/lecture/all/").hasRole(USER_ROLE)
                .antMatchers(HttpMethod.POST, "/member/**").hasRole(ADMIN_ROLE)
                .antMatchers(HttpMethod.DELETE, "/member/delete/**").hasRole(ADMIN_ROLE)
                .antMatchers(HttpMethod.GET, "/member/read/**", "/member/all/").hasRole(USER_ROLE)

                .antMatchers(HttpMethod.GET, "/choice/read/").hasRole(ADMIN_ROLE)
                .antMatchers(HttpMethod.GET, "/choice/all").hasRole(ADMIN_ROLE)
                .antMatchers(HttpMethod.POST, "/choice/create/").hasRole(ADMIN_ROLE)
                .antMatchers(HttpMethod.POST, "/choice/update/").hasRole(ADMIN_ROLE)
                .antMatchers(HttpMethod.GET, "/choice/read/").hasRole(USER_ROLE)
                .antMatchers(HttpMethod.GET, "/choice/all").hasRole(USER_ROLE)

                .antMatchers(HttpMethod.POST, "/subject/create").hasRole(ADMIN_ROLE)
                .antMatchers(HttpMethod.POST, "/note/create").hasRole(USER_ROLE)
                .antMatchers(HttpMethod.POST, "/subject/update").hasRole(ADMIN_ROLE)
                .antMatchers(HttpMethod.POST, "/note/update").hasRole(USER_ROLE)
                .antMatchers(HttpMethod.GET, "/subject/read/**", "/note/read/**").hasRole(ADMIN_ROLE)
                .antMatchers(HttpMethod.GET, "/subject/all", "/note/all").hasRole(ADMIN_ROLE)
                .antMatchers(HttpMethod.DELETE, "/subject/delete/**").hasRole(ADMIN_ROLE)
                .antMatchers(HttpMethod.DELETE, "/note/delete/**").hasRole(USER_ROLE)



                .and()
                .csrf().disable()
                .formLogin().disable();
    }

    @Bean
    public PasswordEncoder encoder(){
        return new BCryptPasswordEncoder();
    }


}
