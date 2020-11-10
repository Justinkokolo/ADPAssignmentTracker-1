package org.assignmentTracker.controller.poll;

import org.assignmentTracker.entity.Group;
import org.assignmentTracker.entity.Poll;
import org.assignmentTracker.entity.User;
import org.assignmentTracker.factory.GroupFactory;
import org.assignmentTracker.factory.PollFactory;
import org.assignmentTracker.factory.UserFactory;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.jupiter.api.TestTemplate;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.List;

import static org.junit.Assert.*;

/**
 * @author: Sinovuyo May
 * Student number: 217298915
 * Desc: Poll controller test class
 * Date: 27 September 2020
 */

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@RunWith(SpringRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)

public class PollControllerTest {

    @Autowired
    private TestRestTemplate restTemplate;
    private static Poll poll;
    private String baseURL = "http://localhost:8080/poll";
    User user1 = UserFactory.createUser("Steve","Biko","blackconsciousness","BantuBiko@gmail.com");

    //security impl

    private static String userName = "Poll";
    private static String password = "Password";
    @Test
    public void a_create() {
        
        Poll poll = PollFactory.createPoll(null,user1,null,"Yes");
        String url = baseURL + "create";
        ResponseEntity<Poll> response = restTemplate.withBasicAuth(userName,password).postForEntity(url,poll, Poll.class);
        assertNotNull(response);
        assertNotNull(response.getBody());
        System.out.println(response);
        System.out.println("Response body"+ response.getBody());

    }

    @Test
    public void d_getAll() {

        String url = baseURL + "getAll";
        HttpHeaders headers = new HttpHeaders();
        HttpEntity <String> entity = new HttpEntity<>(null,headers);
        ResponseEntity <String> responseEntity = restTemplate.withBasicAuth(userName,password).exchange(url, HttpMethod.GET,entity, String.class);
        System.out.println("Get all: "+ responseEntity.getBody());

    }

    @Test
    public void b_read(){

        String url = baseURL + "read"+ poll.getId();
        System.out.println("URL"+url);
        ResponseEntity <Poll> responseEntity = restTemplate.withBasicAuth(userName,password).getForEntity(url,Poll.class);
        assertEquals(poll.getId(),responseEntity.getBody().getId());


    }

    @Test
    public void c_update(){

        Poll update = new Poll.Builder().copy(poll).setVotes("Yes").build();
        String url = baseURL + "update";
        System.out.println("URL:"+ url);
        System.out.println("Updated info:"+update);
        ResponseEntity <Poll>  responseEntity = restTemplate.withBasicAuth(userName,password).postForEntity(url,update,Poll.class);
        assertEquals(poll.getId(), responseEntity.getBody().getId());



    }

    @Test
    public void e_delete(){
        

        String url = baseURL + "delete"+ poll.getId();
        System.out.println("URL:"+ url);
        restTemplate.withBasicAuth(userName,password).delete(url);

    }
}
