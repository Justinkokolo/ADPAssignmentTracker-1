package org.assignmentTracker.service.admin.impl;
import org.assignmentTracker.entity.Admin;
import org.assignmentTracker.repository.admin.IAdminRepository;
import org.assignmentTracker.service.admin.IAdminService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AdminService implements IAdminService{

    @Autowired
    private IAdminRepository repository;


    @Override
    public Set<Admin> getAll() {
        return repository.findAll().stream().collect(Collectors.toSet());
    }


    @Override
    public Admin create(Admin admin) {

            return repository.save(admin);
        }

    @Override
    public Admin read(Integer integer)  {
            return repository.findById(integer).orElse(null);
        }

    @Override
    public Admin update(Admin admin) {
        if (repository.existsById(admin.getId())) return repository.save(admin);
        return null;
    }
    @Override
    public boolean delete(Integer integer) {
        repository.deleteById(integer);

        if (repository.existsById(integer)) return false;
        else return false;
    }
    @Override
    public Set<Admin> getIdGreaterThen500000000() {
        Set<Admin> admins = getAll();
        Set<Admin> largeId = new HashSet<>();
        for(Admin admin : admins){
            if(admin.getId()>500000000){
                largeId.add(admin);
            }
        }
        return largeId;
    }
}
