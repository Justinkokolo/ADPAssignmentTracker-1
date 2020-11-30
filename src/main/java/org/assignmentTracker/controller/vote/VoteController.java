package org.assignmentTracker.controller.vote;

import org.assignmentTracker.Dto.VoteCreateDto;
import org.assignmentTracker.entity.User;
import org.assignmentTracker.entity.Vote;
import org.assignmentTracker.factory.VoteFactory;
import org.assignmentTracker.service.user.impl.UserService;
import org.assignmentTracker.service.vote.impl.VoteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

/**
 * VoteController.java
 *
 * @author Claude De-Tchambila
 * student number: 217035027
 */
@RestController
@RequestMapping("/vote")
public class VoteController {

    @Autowired
    private VoteService voteService;

    @Autowired
    private UserService userService;

    @PostMapping("/create")
    public Vote create(@RequestBody VoteCreateDto vote) {
        User user = userService.read(vote.getVoter());
        Vote newVote = VoteFactory.createVote(user);

        return voteService.create(newVote);
    }

    @GetMapping("/read/{id}")
    public Vote read(@PathVariable int id) {
        return voteService.read(id);
    }

    @PutMapping("/update")
    public Vote update(@RequestBody Vote vote) {
        return voteService.update(vote);
    }

    @DeleteMapping("/delete/{id}")
    public void delete(@PathVariable int id) {
        voteService.delete(id);
    }

    @GetMapping("/all")
    public Set<Vote> getAll() {
        return voteService.getAll();
    }

    @GetMapping("/all/username")
    public Set<Vote> getAllByUsername(@RequestHeader String username) {
        return voteService.getVoteByUsername(username);
    }

}
