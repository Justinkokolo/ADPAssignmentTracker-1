package org.assignmentTracker.factoryTest;

import org.assignmentTracker.entity.Group;
import org.assignmentTracker.entity.Lecture;
import org.assignmentTracker.entity.Subject;
import org.assignmentTracker.factory.GroupFactory;
import org.assignmentTracker.factory.SubjectFactory;
import org.junit.Assert;
import org.junit.Test;

import java.util.Date;

import static org.assignmentTracker.factory.UserFactory.createUser;

/**
 * @author : Sinovuyo May
 * Student no: 217298915
 * Date : 05 July 2020
 * Desc: createGroup method test class
 */


public class GroupFactoryTest {

    @Test
    public void createGroup() {

        Subject subject = SubjectFactory.createSubject("Application Development Practice","ADP372S","DDD Part 2",new Date());
        //lecture factory entity has not yet been created
        Group group = new GroupFactory().createGroup("Group 13",null,null);

        Assert.assertEquals(group.getName(),null);

    }
}