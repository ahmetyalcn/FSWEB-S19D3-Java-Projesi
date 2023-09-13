package com.workintech.auth.service;

import com.workintech.auth.dao.StudentRepository;
import com.workintech.auth.entity.Student;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class StudentServiceImpl implements StudentService{
    private StudentRepository studentRepository;
    @Autowired
    public StudentServiceImpl(StudentRepository studentRepository) {
        this.studentRepository = studentRepository;
    }

    @Override
    public List<Student> findAll() {
        return studentRepository.findAll();
    }

    @Override
    public Student findById(int id) {
        return studentRepository.findById(id).orElseThrow();
    }

    @Override
    public Student save(Student student) {
        return studentRepository.save(student);
    }

    @Override
    public Student delete(String tckn) {
        Optional<Student> founded = studentRepository.findStudentByTckn(tckn);
        if (founded.isPresent()){
            studentRepository.delete(founded.get());
            return founded.get();
        }
        return null;
    }
}
