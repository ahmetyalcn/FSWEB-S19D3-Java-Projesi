package com.workintech.auth.dao;

import com.workintech.auth.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AccountRepository extends JpaRepository<Account,Integer> {

}
