package org.assignmentTracker.entity;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.OneToOne;

/*
@author Brandon Villet
StudNo: 214056791
Date: 29 June 2020
Desc: Admin class
 */
@Entity
public class Admin {
    protected Admin(){}

    @Id
    private  int id;
    @OneToOne
    private  Assignment assignment;
    private  User user;


    public Admin(Builder builder) {
        this.id = builder.id;
        this.assignment = builder.assignment;
        this.user = builder.user;
    }//end of constructor

    public static class Builder {

        private int id;
        private Assignment assignment;
        private User user;

        public Builder setId(int id){

            this.id= id ;
            return this;
        }

        public Builder setUser(User user) {
            this.user = user;
            return this;
        }

        public Builder setAssignment(Assignment assignment) {
            this.assignment = assignment;
            return this;
        }

        public Builder copy(Admin admin) {

            this.id = admin.id;
            this.assignment = admin.assignment;
            this.user = admin.user;
            return this;
        }

        public Admin build(){return new Admin(this);}

    }// end of builder class



    public int getId() {
        return id;
    }

    public Assignment getAssignment() {
        return assignment;
    }

    public User getUser() {
        return user;
    }

    @java.lang.Override
    public java.lang.String toString() {
        return "Admin{" +
                "id=" + id +
                ", user=" + user +
                ", assignment=" + assignment +
                '}';
    }
}//end of main class
