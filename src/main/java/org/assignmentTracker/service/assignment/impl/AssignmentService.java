package org.assignmentTracker.service.assignment.impl;

import org.assignmentTracker.entity.Assignment;
import org.assignmentTracker.entity.Subject;
import org.assignmentTracker.repository.assignment.IAssignmentRepository;
import org.assignmentTracker.service.assignment.IAssignmentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * AssignmentService.java
 * Assignment service implementation
 * Date: 06 August 2020
 * @author Claude Christ De-Tchambila
 * student number: 217035027
 */
@Service
public class AssignmentService implements IAssignmentService {

    @Autowired
    private IAssignmentRepository repository;

    @Override
    public Set<Assignment> getAll() {
        return repository.findAll().stream().collect(Collectors.toSet());
    }

    @Override
    public Set<Assignment> getAssignmentsByDate(Date date) {
        Set<Assignment> assignmentSet = getAll();
        assignmentSet.removeIf(assignment -> !assignment.getDateAssigned().equals(date));
        return assignmentSet;
    }

    @Override
    public Set<Assignment> getAssignmentsBySubject(String subject) {
        Set<Assignment> assignmentSet = getAll();
        assignmentSet.removeIf(assignment -> !assignment.getSubject().getName().equals(subject));
        return assignmentSet;
    }

    @Override
    public Set<Assignment> getAssignmentsContainName(String name) {
        Set<Assignment> assignmentSet = getAll();
        assignmentSet.removeIf(assignment -> !assignment.getName().contains(name));
        return assignmentSet;
    }

    @Override
    public Assignment create(Assignment assignment) {
        return repository.save(assignment);
    }

    @Override
    public Assignment read(Integer integer) {
        return repository.findById(integer).orElse(null);
    }

    @Override
    public Assignment update(Assignment assignment) {
        if (repository.existsById(assignment.getId())) return repository.save(assignment);
        return null;
    }

    @Override
    public boolean delete(Integer id) {
        repository.deleteById(id);

        if (repository.existsById(id)) return false;
        else return false;
    }

}