package com.security.secure.auth;

import com.google.common.collect.Lists;
import com.security.secure.security.ApplicationUserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static com.security.secure.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao{

    private PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUserName(String username) {
        return getApplicationUsers().stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        STUDENT.getGrantedAuthorities(),
                         "anna",
                         passwordEncoder.encode("pass"),
                        true,
                        true,
                        true,
                        true
                ),

                new ApplicationUser(
                        ADMIN.getGrantedAuthorities(),
                        "linda",
                        passwordEncoder.encode("pass123"),
                        true,
                        true,
                        true,
                        true
                ),

                new ApplicationUser(
                        ADMINTRAINEE.getGrantedAuthorities(),
                        "tom",
                        passwordEncoder.encode("pass123"),
                        true,
                        true,
                        true,
                        true
                )
        );

        return applicationUsers;
    }

}
