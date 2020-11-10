package org.assignmentTracker.serviceTest;

import org.assignmentTracker.entity.Group;
import org.assignmentTracker.factory.GroupFactory;
import org.assignmentTracker.service.group.GroupService;
import org.assignmentTracker.service.group.impl.GroupServiceImpl;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Set;

import static org.junit.Assert.*;

/**
 * @author: Sinovuyo May
 * Student number: 217298915
 * Desc: Test class for GroupService
 * Date: 06 September 2020
 */

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class GroupServiceImplTest {

    @Autowired
    private static GroupService service ;
    private static Group group = GroupFactory.createGroup("Group 13",
            null,null);


    @Test
    public void d_getAll() {

        Set<Group> group = service.getAll();
        assertEquals(1,group.size());
        System.out.println("Group"+ group);
    }

    @Test
    public void a_create() {

        Group created = service.create(group);
        Assert.assertEquals(group.getId() , created.getId());
        System.out.println("Created: "+ created);
    }

    @Test
    public void b_read() {

        Group read = service.read(group.getId());
        System.out.println("Read: "+ read);
    }

    @Test
    public void c_update() {

        Group update = new Group.Builder().copy(group).setName("Group thirteen").build();
        update = service.update(update);
        System.out.println("Update: "+ update);
    }

    @Test
    public void e_delete() {

        boolean deleted = service.delete(group.getId());
        Assert.assertTrue(deleted);
    }
}