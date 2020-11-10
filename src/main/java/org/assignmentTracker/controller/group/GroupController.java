package org.assignmentTracker.controller.group;

import org.assignmentTracker.entity.Group;
import org.assignmentTracker.factory.GroupFactory;
import org.assignmentTracker.service.group.impl.GroupServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

/**
 * @author: Sinovuyo May
 * Student number: 217298915
 * Desc: Group controller
 * Date: 27 September 2020
 */
@RestController
@RequestMapping("/group")
public class GroupController {

    @Autowired
    private GroupServiceImpl groupService;

        @PostMapping("/create")
    public Group create(@RequestBody Group group){

            Group newGroup = GroupFactory.createGroup(group.getName(),
                    group.getLecture(),
                    group.getSubject());

            return groupService.create(newGroup);
        }

        public Set<Group> getAll(){

            return groupService.getAll();
        }

    @GetMapping("/read/{integer}")
    public Group read(@RequestBody Integer integer){
            return groupService.read(integer);
    }

    @PostMapping("/update")
    public Group update(@RequestBody Group group){

            return groupService.update(group);
    }

    @DeleteMapping("/delete/{integer}")
    public boolean delete(@PathVariable Integer integer){

        return groupService.delete(integer);

    }
}
