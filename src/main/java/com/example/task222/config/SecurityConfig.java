package com.example.task222.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser("superAdmin")
                .password(passwordEncoder().encode("admin"))
                .roles("SUPER_ADMIN")
                .and()
                .withUser("moderator")
                .password(passwordEncoder().encode("moder"))
                .roles("MODERATOR")
                .and()
                .withUser("operator")
                .password(passwordEncoder().encode("oper"))
                .roles("OPERATOR");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers(HttpMethod.GET, "/api/order").hasAnyRole("OPERATOR", "SUPER_ADMIN")
                .antMatchers(HttpMethod.POST, "/api/order").hasAnyRole("OPERATOR", "SUPER_ADMIN")
                .antMatchers(HttpMethod.DELETE, "/api/order/*").hasAnyRole( "SUPER_ADMIN")
                .antMatchers(HttpMethod.PUT, "/api/order/*").hasAnyRole( "SUPER_ADMIN")
                .antMatchers(HttpMethod.GET, "/api/product").hasAnyRole("MODERATOR", "SUPER_ADMIN")
                .antMatchers(HttpMethod.POST, "/api/product").hasAnyRole("MODERATOR", "SUPER_ADMIN")
                .antMatchers(HttpMethod.PUT, "/api/product/*").hasAnyRole("MODERATOR", "SUPER_ADMIN")
                .antMatchers(HttpMethod.DELETE, "/api/product/*").hasRole("SUPER_ADMIN")
                .antMatchers().hasRole("SUPER_ADMIN")
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();

    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /*
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication() //The memory which is used in Spring Context
                .withUser("director1")
                .password(passwordEncoder().encode("director1"))
                .roles("DIRECTOR")
*/
    /*
                .authorities("READ_ALL_PRODUCTS", "EDIT_PRODUCT", "ADD_PRODUCT", "DELETE_PRODUCT", "READ_ONE_PRODUCT")
                .and()
                .withUser("director2")
                .password(passwordEncoder().encode("director2"))
                .roles("DIRECTOR")
                .authorities("READ_ALL_PRODUCTS", "EDIT_PRODUCT", "ADD_PRODUCT", "READ_ONE_PRODUCT")
*/
    /*

                .and()
                .withUser("manager")
                .password(passwordEncoder().encode("manager"))
                .roles("MANAGER")
                .and()
                .withUser("user")
                .password(passwordEncoder().encode("user"))
                .roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()       //cross site request forgery - csrf. When csrf is on, perpetrator can not make fake request.
                .authorizeRequests()
                .antMatchers(HttpMethod.GET,"/api/product/*").hasAnyRole("USER", "MANAGER", "DIRECTOR")
                .antMatchers(HttpMethod.GET,"/api/product").hasAnyRole("MANAGER","DIRECTOR")   //the role which has fewer privileges must be in upper position
                .antMatchers("/api/product").hasRole("DIRECTOR")
                //.antMatchers(HttpMethod.DELETE,"/api/product/*").hasAnyAuthority("DELETE_PRODUCT")       //Can delete only a director who has DELETE_PRODUCT authority/privilege
                //.antMatchers("/api/product").hasAnyAuthority("READ_ALL_PRODUCTS", "EDIT_PRODUCT", "ADD_PRODUCT", "READ_ONE_PRODUCT")
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic(); //Why basic authentication? Because in Postman we can not work with Form based authentication or it is difficult.


    }

*/

}
