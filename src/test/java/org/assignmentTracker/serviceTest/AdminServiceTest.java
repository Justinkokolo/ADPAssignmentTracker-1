package org.assignmentTracker.serviceTest;

import org.assignmentTracker.entity.Admin;
import org.assignmentTracker.entity.User;
import org.assignmentTracker.factory.AdminFactory;
import org.assignmentTracker.factory.UserFactory;
import org.assignmentTracker.service.admin.IAdminService;
import org.assignmentTracker.service.admin.impl.AdminService;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import static org.assignmentTracker.factory.UserFactory.createUser;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AdminServiceTest {

    private static IAdminService service ;
    private static User user1 = createUser("Brandon", "Villet", "pass", "villetbrandon@gmail.com");
    private static User user2 = UserFactory.createUser("Byron", "Cloete", "wordpass", "byroncloete7@gmail.com");
    private static Admin admin1 = AdminFactory.createAdmin(user1, null);
    private static Admin admin2 = AdminFactory.createAdmin(user2, null);

    @Test
    public void a_create() {
        Admin createdAdmin1 = service.create(admin1);
        Admin createdAdmin2 = service.create(admin2);
        Assert.assertEquals(createdAdmin1.getId(), admin1.getId());
        Assert.assertEquals(createdAdmin2.getId(), admin2.getId());
        Assert.assertNotEquals(createdAdmin1.getId(), createdAdmin2.getId());
        System.out.println(("Created: " + createdAdmin1 + "\n" + createdAdmin1) );
    }
    @Test
    public void b_read() {
        Admin read1st = service.read(admin1.getId());
        Admin read2nd = service.read(admin2.getId());
        System.out.println("Read: " +read1st+ "\n" + read2nd);
    }
    @Test
    public void c_update() {
        User userUpdated = new User.Builder().copy(user1).setName("John").build();
        Admin updated = new Admin.Builder().copy(admin1).setUser(userUpdated).build();
        updated = service.update(updated);
        System.out.println("Updated: " + updated);
    }
    @Test
    public void d_getAll() {
        System.out.println("Get all: " + service.getAll());
    }
    @Test
    public void e_getIdGreaterThen500000000() {

        System.out.println("Id numbers greater then 500000000:" + service.getIdGreaterThen500000000());
    }
    @Test
    public void f_delete() {
        boolean deleted = service.delete(admin1.getId());
        Assert.assertTrue(deleted);
        System.out.println("Deleted: " + admin1);

    }
}
