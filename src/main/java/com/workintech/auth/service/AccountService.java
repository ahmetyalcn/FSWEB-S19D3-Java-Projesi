package com.workintech.auth.service;

import com.workintech.auth.entity.Account;

import java.util.List;

public interface AccountService {
    List<Account> findAll();
    Account findById(int id);
    Account save(Account account);
    Account delete(int id);
}
