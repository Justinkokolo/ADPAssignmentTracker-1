package org.assignmentTracker.repository.lecture;

import org.assignmentTracker.entity.Lecture;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Set;

/**
 * @author Justin Kokolo
 * student number: 218044194
 * Desc:
 * Date: 28 August 2020
 */

@Repository
public interface LectureRepository extends JpaRepository<Lecture, Integer> {

}
