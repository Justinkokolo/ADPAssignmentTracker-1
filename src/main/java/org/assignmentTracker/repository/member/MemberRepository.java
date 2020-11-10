package org.assignmentTracker.repository.member;

import org.assignmentTracker.entity.Member;
import org.assignmentTracker.repository.IRepository;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Set;

/**
 * @author Justin Kokolo
 * student number: 218044194
 * Desc: member interface
 * Date: 28 August 2020
 */

public interface MemberRepository extends JpaRepository<Member,Integer> {

//    Set<Member> getAll();
}