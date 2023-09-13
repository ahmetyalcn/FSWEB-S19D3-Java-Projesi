package com.workintech.auth.service;

import com.workintech.auth.dao.AccountRepository;
import com.workintech.auth.dao.MemberRepository;
import com.workintech.auth.dao.RoleRepository;
import com.workintech.auth.dto.LoginResponse;
import com.workintech.auth.entity.Member;
import com.workintech.auth.entity.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
public class AuthenticationService {
    private PasswordEncoder passwordEncoder;
    private MemberRepository memberRepository;
    private RoleRepository roleRepository;
    private AuthenticationManager authenticationManager;
    private TokenService tokenService;

    @Autowired
    public AuthenticationService(PasswordEncoder passwordEncoder, MemberRepository memberRepository,
                                 RoleRepository roleRepository, AuthenticationManager authenticationManager,
                                 TokenService tokenService) {
        this.passwordEncoder = passwordEncoder;
        this.memberRepository = memberRepository;
        this.roleRepository = roleRepository;
        this.authenticationManager = authenticationManager;
        this.tokenService = tokenService;
    }



    public Member register(String email, String password){
        Optional<Member> foundMember = memberRepository.findMemberByEmail(email);
        if(foundMember.isPresent()){
            //throw Exception
            return null;
        }

        String encodedPassword = passwordEncoder.encode(password);
        Role memberRole = roleRepository.findByAuthority("USER").get();
        Set<Role> roles = new HashSet<>();
        roles.add(memberRole);

        Member member = new Member();
        member.setEmail(email);
        member.setPassword(encodedPassword);
        member.setAuthorities(roles);
        return memberRepository.save(member);
    }

    public LoginResponse login(String email, String password){
        try {
            Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email,password));
            String token = tokenService.generateJwtToken(auth);
            return new LoginResponse(memberRepository.findMemberByEmail(email).get(),token);

        }catch (AuthenticationException ex){
            return new LoginResponse(null,"");
        }
    }
}
