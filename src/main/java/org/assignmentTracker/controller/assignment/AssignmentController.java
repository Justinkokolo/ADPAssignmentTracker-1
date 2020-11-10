package org.assignmentTracker.controller.assignment;

import org.assignmentTracker.entity.Assignment;
import org.assignmentTracker.factory.AssignmentFactory;
import org.assignmentTracker.service.assignment.impl.AssignmentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

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
