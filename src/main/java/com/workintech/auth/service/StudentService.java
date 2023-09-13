package com.workintech.auth.service;

import com.workintech.auth.entity.Student;

import java.util.List;

public interface StudentService {
    List<Student> findAll();
    Student findById(int id);
    Student save(Student student);
    Student delete(String tckn);

}
