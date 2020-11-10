package org.assignmentTracker.service.member.imp;

/**
 * @author Justin Kokolo
 * student number: 218044194
 * Desc: member interface implematation
 * Date: 04 September 2020
 */


import org.assignmentTracker.entity.Member;
import org.assignmentTracker.repository.member.MemberRepository;
import org.assignmentTracker.service.member.IMemberService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class MemberServiceImpl implements IMemberService {

    private static IMemberService service = null;
    @Autowired
    private MemberRepository repository;



    @Override
    public Set<Member> getAll() {
        return this.repository.findAll().stream().collect(Collectors.toSet());
    }

    @Override
    public Set<Member> getAllNamesThatStartWithK() {

        Set<Member> member =getAll();
        Set<Member> MembersWith1 = new HashSet<>();
        for(Member  m : member){

            if ( m.getAssignment_id() == 123){
                MembersWith1.add(m);
            }

        }
        return MembersWith1;

    }

    @Override
    public Member create(Member member) {

        return this.repository.save(member);
    }

    @Override
    public Member read(Integer id) {

        return this.repository.findById(id).orElseGet(null);
    }

    @Override
    public Member update(Member member) {

        return this.repository.save(member);
    }

    @Override
    public boolean delete(Integer id) {

        this.repository.deleteById(id);
        if(this.repository.existsById(id)) return false;
        else return true;
    }
}
