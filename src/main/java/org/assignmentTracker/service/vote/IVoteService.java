package org.assignmentTracker.service.vote;

import org.assignmentTracker.entity.Vote;
import org.assignmentTracker.service.IService;
import org.springframework.stereotype.Service;

import java.util.Set;

/**
 * IVoteService.java
 * Vote service interface
 * Date: 06 August 2020
 * @author Claude Christ De-Tchambila
 * student number: 217035027
 */
@Service
public interface IVoteService extends IService<Vote, Integer> {
    Set<Vote> getAll();
    Set<Vote> getVoteByUsername(String username);
}