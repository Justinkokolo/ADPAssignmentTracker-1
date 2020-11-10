package org.assignmentTracker.controller.group;

import org.assignmentTracker.entity.Group;
import org.assignmentTracker.entity.Poll;
import org.assignmentTracker.factory.GroupFactory;
import org.junit.FixMethodOrder;
import org.junit.Test;
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

import static org.junit.Assert.*;

/**
 * @author: Sinovuyo May
 * Student number: 217298915
 * Desc: Group controller test class
 * Date: 27 September 2020
 */

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@RunWith(SpringRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)

public class GroupControllerTest {

    @Autowired
    private TestRestTemplate restTemplate;
    private static  Group group = GroupFactory.createGroup( "Group 13",null,null);;
    private String baseURL = "http://localhost:8080/group";

//    Group group = GroupFactory.createGroup( "Group 13",null,null);
   // Group group = GroupFactory.createGroup( "Group 13","Mr WC Rothman","Project 3");

    //security impl

    private static String userName = "Group13";
    private static String password = "Team";


    @Test
    public void create() {

        
        String url = baseURL + "create";
        ResponseEntity <Group> response = restTemplate.withBasicAuth(userName,password).postForEntity(url,group, Group.class);
        assertNotNull(response);
        assertNotNull(response.getBody());
        System.out.println(response);
        System.out.println("Response body: "+ response.getBody());
        System.out.println("Http response code: " +response.getStatusCodeValue());
    }

    @Test
    public void getAll() {

        String url = baseURL + "getAll";
        HttpHeaders headers = new HttpHeaders();
        HttpEntity<String> entity = new HttpEntity<>(null,headers);
        ResponseEntity <String> responseEntity = restTemplate.withBasicAuth(userName,password).exchange(url, HttpMethod.GET,entity, String.class);
        System.out.println("Get all: "+ responseEntity.getBody());
    }

    @Test
    public void b_read(){

        String url = baseURL + "read"+ group.getId();
        System.out.println("URL"+url);
        ResponseEntity <Group> responseEntity = restTemplate.withBasicAuth(userName,password).getForEntity(url,Group.class);
        assertEquals(group.getId(),responseEntity.getBody().getId());


    }

    @Test
    public void c_update(){

        Group update = new Group.Builder().copy(group).setName("Group thirteen").build();
        String url = baseURL + "update";
        System.out.println("URL:"+ url);
        System.out.println("Updated info:"+update);
        ResponseEntity <Group>  responseEntity = restTemplate.withBasicAuth(userName,password).postForEntity(url,update,Group.class);
        assertEquals(group.getId(), responseEntity.getBody().getId());



    }

    @Test
    public void e_delete(){

        String url = baseURL + "delete"+ group.getId();
        System.out.println("URL:"+ url);
        restTemplate.withBasicAuth(userName,password).delete(url);

    }
}
