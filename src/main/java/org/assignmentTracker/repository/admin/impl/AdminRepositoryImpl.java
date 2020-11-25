/*package org.assignmentTracker.repository.admin.impl;

import org.assignmentTracker.entity.Admin;
import org.assignmentTracker.repository.admin.IAdminRepository;
import java.util.HashSet;
import java.util.Set;


 * @author Brandon Villet
 * student number: 214056791
 * Desc: Interface for admin repository
 * Date: 30 August 2020


public class AdminRepositoryImpl implements IAdminRepository {
    private static AdminRepositoryImpl repository = null;
    private Set<Admin> adminDB;

    public AdminRepositoryImpl() {
        this.adminDB = new HashSet<Admin>();
    }
    public static AdminRepositoryImpl getRepo(){
        if(repository == null) repository = new AdminRepositoryImpl();
        return repository;
    }

    @Override
    public Set<Admin> getAll() {
        return this.adminDB;
    }

    @Override
    public Admin create(Admin admin) {
        this.adminDB.add(admin);
        return admin;
    }


    @Override
    public Admin read(Integer integer) {
        for (Admin admin : this.adminDB){
            if(admin.getId() == integer) return admin;
        }
        return null;
    }


    @Override
    public Admin update(Admin admin) {
        boolean deleteAdmin = delete(admin.getId());
        if(deleteAdmin){
            this.adminDB.add(admin);
            return admin;
        }
        return null;
    }

    @Override
    public boolean delete(Integer integer) {
        Admin admin = read(integer);
        if(admin != null){
            this.adminDB.remove(admin);
            return true;
        }
        return false;
    }}
*/