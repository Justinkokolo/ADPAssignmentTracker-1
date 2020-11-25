package org.assignmentTracker.controller.assignment;

import org.assignmentTracker.entity.Assignment;
import org.assignmentTracker.entity.Subject;
import org.assignmentTracker.factory.AssignmentFactory;
import org.assignmentTracker.service.assignment.impl.AssignmentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

/**
 * AssignmentController.java
 *
 * @author Claude De-Tchambila
 * student number: 217035027
 */
@RestController
@RequestMapping("/assignment")
public class AssignmentController {

    @Autowired
    private AssignmentService assignmentService;

    @PostMapping("/create")
    public Assignment create(@RequestBody Assignment assignment) {
        Assignment newAssignment = AssignmentFactory.createAssignment(
                assignment.getName(),
                assignment.getSubject(),
                assignment.getDateAssigned(),
                assignment.getAdmins(),
                assignment.getMembers(),
                assignment.getCreator());

        return assignmentService.create(newAssignment);
    }

    @GetMapping("/read/{id}")
    public Assignment read(@PathVariable int id) {
        return assignmentService.read(id);
    }

    @GetMapping("/all/date")
    public Set<Assignment> readByDate(@RequestHeader String dateString) {
        Date date = null;
        try {
            date = new SimpleDateFormat("dd,MM,yyyy").parse(dateString);
        } catch (ParseException e) {
            e.printStackTrace();
        }
        if (date != null)
            return assignmentService.getAssignmentsByDate(date);;

        return new HashSet<>();
    }

    @GetMapping("/all/subject")
    public Set<Assignment> readBySubjectName(@RequestHeader String subjectName) {
        return assignmentService.getAssignmentsBySubject(subjectName);
    }

    @GetMapping("/all/name")
    public Set<Assignment> readByName(@RequestHeader String assignmentName) {
        return assignmentService.getAssignmentsContainName(assignmentName);
    }

    @PutMapping("/update")
    public Assignment update(@RequestBody Assignment assignment) {
        return assignmentService.update(assignment);
    }

    @DeleteMapping("/delete/{id}")
    public void delete(@PathVariable int id) {
        assignmentService.delete(id);
    }

    @GetMapping("/all")
    public Set<Assignment> getAll() {
        return assignmentService.getAll();
    }


}
