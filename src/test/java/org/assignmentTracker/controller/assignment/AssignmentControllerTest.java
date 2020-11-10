package org.assignmentTracker.controller.assignment;

import org.assignmentTracker.entity.Assignment;
import org.assignmentTracker.factory.AssignmentFactory;
import org.assignmentTracker.factory.SubjectFactory;
import org.assignmentTracker.factory.UserFactory;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Date;
import java.util.List;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@RunWith(SpringRunner.class)
public class AssignmentControllerTest {

    @Autowired
    private TestRestTemplate restTemplate;
    private static Assignment assignment;
    private final String baseUrl = "http://localhost:8080/assignment";
    private final static String SECURITY_USERNAME = "Byron";
    private final static String SECURITY_PASSWORD = "password";

    @Test
    public void a_create() {
        Assignment newAssignment = AssignmentFactory.createAssignment("Project Deliverable 3",
                SubjectFactory.createSubject("Project 3", "PRT362S", "Rothman", new Date()),
                new Date(),
                null,
                null,
                UserFactory.createUser("Martin", "Fowler", "123123", "martin@email.com")
        );
        String url = baseUrl + "/create";
        ResponseEntity<Assignment> postResponse = restTemplate
                .withBasicAuth(SECURITY_USERNAME, SECURITY_PASSWORD)
                .postForEntity(url, newAssignment, Assignment.class);

        assertNotNull(postResponse.getBody());
        assertEquals(HttpStatus.OK, postResponse.getStatusCode());
        assignment = postResponse.getBody();

        System.out.println("Create vote");

        System.out.println("Response body");
        System.out.println(postResponse.getBody());
        System.out.println("Response status code");
        System.out.println(postResponse.getStatusCodeValue());
    }

    @Test
    public void b_read() {
        int id = assignment.getId();
        String url = baseUrl + "/read/" + id;

        ResponseEntity<Assignment> getResponse = restTemplate
                .withBasicAuth(SECURITY_USERNAME, SECURITY_PASSWORD)
                .getForEntity(url, Assignment.class);

        assertNotNull(getResponse.getBody());
        assertEquals(HttpStatus.OK, getResponse.getStatusCode());

        System.out.println("Read assignment");
        System.out.println(getResponse.getBody());
        System.out.println(getResponse.getStatusCodeValue());
    }

    @Test
    public void c_update() {
        String url = baseUrl + "/update";
        String oldName = assignment.getName();

        assignment.setName("Deliverable 3");

        restTemplate.withBasicAuth(SECURITY_USERNAME, SECURITY_PASSWORD)
                .put(url, assignment);

        url = baseUrl + "/read/" + assignment.getId();

        ResponseEntity<Assignment> response = restTemplate
                .withBasicAuth("Robyn", "wordpasss")
                .getForEntity(url, Assignment.class);

        Assignment assignmentFromDb = response.getBody();
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertNotEquals(assignmentFromDb.getName(), oldName);
    }

    @Test
    public void e_delete() {
        String url = baseUrl + "/delete/" + assignment.getId();
        restTemplate.delete(url);

        ResponseEntity<List> response = restTemplate
                .withBasicAuth(SECURITY_USERNAME, SECURITY_PASSWORD)
                .getForEntity(baseUrl + "/all", List.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());

        System.out.println(response.getBody());
        System.out.println(response.getStatusCode());
    }

    @Test
    public void d_getAll() {
        String url = baseUrl + "/all";
        HttpHeaders headers = new HttpHeaders();
        HttpEntity<String> entity = new HttpEntity<>(null, headers);
        ResponseEntity<String> response = restTemplate
                .withBasicAuth(SECURITY_USERNAME, SECURITY_PASSWORD)
                .exchange(url, HttpMethod.GET, entity, String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());

        System.out.println("Get all assignments");
        System.out.println(response.getBody());
    }
}