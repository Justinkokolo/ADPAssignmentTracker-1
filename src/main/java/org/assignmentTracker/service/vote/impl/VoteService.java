package org.assignmentTracker.service.vote.impl;

import org.assignmentTracker.entity.Assignment;
import org.assignmentTracker.entity.Vote;
import org.assignmentTracker.repository.vote.IVoteRepository;
import org.assignmentTracker.service.vote.IVoteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;


/**
 * VoteService.java
 * Vote service implementation
 * Date: 06 August 2020
 * @author Claude Christ De-Tchambila
 * student number: 217035027
 */
@Service
public class VoteService implements IVoteService {

    @Autowired
    private IVoteRepository repository;

    @Override
    public Set<Vote> getAll() {
        return repository.findAll().stream().collect(Collectors.toSet());
    }

    @Override
    public Set<Vote> getVoteByUsername(String username) {
        Set<Vote> voteSet = getAll();
        voteSet.removeIf(vote -> !vote.getVoter().getName().equalsIgnoreCase(username));
        return voteSet;
    }

    @Override
    public Vote create(Vote vote) {
        return repository.save(vote);
    }

    @Override
    public Vote read(Integer integer) {
        return repository.findById(integer).orElse(null);
    }

    @Override
    public Vote update(Vote vote) {
        if (repository.existsById(vote.getId())) return repository.save(vote);
        return null;
    }

    @Override
    public boolean delete(Integer id) {
        repository.deleteById(id);

        if (repository.existsById(id)) return false;
        else return false;
    }
}


