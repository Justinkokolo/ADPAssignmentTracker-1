package org.assignmentTracker.factory;

import org.assignmentTracker.entity.Group;
import org.assignmentTracker.entity.Lecture;
import org.assignmentTracker.entity.Subject;
import org.assignmentTracker.util.Helper;

/**
 * @author : Sinovuyo May
 * Student no: 217298915
 * Date : 05 July 2020
 * Desc: Group factory entity
 */

public class GroupFactory {


    public static Group createGroup (String name, Lecture lecture, Subject subject){

        int groupID = Helper.generateID();
        Group group = new Group.Builder()
                .setId(groupID)
                .setName(name)
                .setLecture(lecture)
                .setSubject(subject)
                .build();
        return group;
    }

}
