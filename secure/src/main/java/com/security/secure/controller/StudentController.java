package com.security.secure.controller;

import com.security.secure.model.Student;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/student")
public class StudentController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "anna"),
            new Student(2, "linda"),
            new Student(3, "tom")
    );

    @GetMapping(path = "{studentId}")
    public Student getStudent(@PathVariable("studentId") String studentId){
        return STUDENTS.stream()
                .filter(student -> studentId.equals(student.getStudentId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("student " + studentId + " not found Exception"));
    }
}
