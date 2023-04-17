package com.shalaka.springjwt.service;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class CustomUserDetailService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<SimpleGrantedAuthority> roles=null;
        if(username.equals("admin"))
        {
            roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"));
            return new User("admin", "$2a$10$WA3jdWuBS2QF10mqSLz3T.zglo/VX0yjfLcLGQN7gj78MEsiVK/mG",
                    roles);
        } else if(username.equals("user")) {
            roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"));
            return new User("user", "$2a$10$XWc6qPGA1pK7Jnwklr4qWO8jfGvh9QkQWr0GWVl0qi.Hg/vEmAKeS",
                    roles);
        }
        throw new UsernameNotFoundException("User not found with username: " + username);

    }
}
