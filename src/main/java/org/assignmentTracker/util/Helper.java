package org.assignmentTracker.util;

import java.util.Random;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

public class Helper {

    public static int generateID(){
        int min = 1000;
        int max = 9999;
        return ThreadLocalRandom.current().nextInt(min, max + 1);
    }

    public static long generateStudNum(){
        int min = 100000000;
        int max = 999999999;
        return (long) ThreadLocalRandom.current().nextInt(min, max + 1);
    }

    public static int generateAssignmentId() {
        int min = 100000000;
        int max = 999999999;
        return ThreadLocalRandom.current().nextInt(min, max + 1);
    }

    public static int generateVoteId() {
        int min = 100000000;
        int max = 999999999;
        return ThreadLocalRandom.current().nextInt(min, max + 1);
    }


}
