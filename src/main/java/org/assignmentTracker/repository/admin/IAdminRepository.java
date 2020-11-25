package org.assignmentTracker.repository.admin;

import org.assignmentTracker.entity.Admin;
import org.assignmentTracker.repository.IRepository;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Set;
/**
 * @author Brandon Villet
 * student number: 214056791
 * Desc: Interface for admin repository
 * Date: 30 August 2020
 */
@Repository
public interface IAdminRepository extends JpaRepository<Admin,Integer> {


}