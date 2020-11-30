package org.assignmentTracker.service.assignment;

import org.assignmentTracker.entity.Assignment;
import org.assignmentTracker.entity.Subject;
import org.assignmentTracker.service.IService;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Set;

/**
 * IAssigmentService.java
 * Assignment service interface
 * Date: 06 August 2020
 * @author Claude Christ De-Tchambila
 * student number: 217035027
 */
@Service
public interface IAssignmentService extends IService<Assignment, Integer> {
    Set<Assignment> getAll();
    Set<Assignment> getAssignmentsByDate(Date date);
    Set<Assignment> getAssignmentsBySubject(String subject);
    Set<Assignment> getAssignmentsContainName(String name);

}