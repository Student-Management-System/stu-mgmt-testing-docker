package net.ssehub.studentmgmt.docker;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import net.ssehub.studentmgmt.backend_api.api.DefaultApi;
import net.ssehub.studentmgmt.docker.StuMgmtDocker.AssignmentState;
import net.ssehub.studentmgmt.docker.StuMgmtDocker.Collaboration;
import net.ssehub.studentmgmt.sparkyservice_api.api.RoutingControllerApi;

public class StuMgmtDockerIT {

    @Test
    public void servicesReachable() {
        try (StuMgmtDocker docker = new StuMgmtDocker()) {
            assertAll(
                () -> assertAuthSystemAlive(docker.getAuthUrl()),
                () -> assertStuMgmtAlive(docker.getStuMgmtUrl()),
                () -> assertHttpServerReachable(docker.getWebUrl())
            );
        }
    }
    
    @Test
    public void stuMgmtOperationsDoNotThrow() {
        try (StuMgmtDocker docker = new StuMgmtDocker()) {
            assertDoesNotThrow(() -> {
                docker.createUser("teacher", "abcdefgh");
                docker.createUser("student1", "123456");
                docker.createUser("student2", "654321");
                
                String course = docker.createCourse("docker", "wise2122", "Introduction to Docker", "teacher");
                
                docker.enrollStudent(course, "student1");
                docker.enrollStudent(course, "student2");
                docker.createGroup(course, "SomeGroup", "student1", "student2");
                
                String assignment = docker.createAssignment(course, "Assignment01", AssignmentState.INVISIBLE, Collaboration.GROUP);
                docker.changeAssignmentState(course, assignment, AssignmentState.SUBMISSION);
            });
        }
    }
    
    @Test
    public void createUserWithPasswordShorterThan6CharsThrows() {
        try (StuMgmtDocker docker = new StuMgmtDocker()) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> docker.createUser("user", "12345"));
            assertEquals("Password must be at least 6 characters", e.getMessage());
        }
    }
    
    @Test
    public void createCourseWithInvalidSemesterThrows() {
        try (StuMgmtDocker docker = new StuMgmtDocker()) {
            docker.createUser("teacher", "123456");
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> docker.createCourse("test", "invalid", "Test", "teacher"));
            assertEquals("Semester must match be in the form of sose21 or wise2122", e.getMessage());
        }
    }
    
    @Test
    public void createCourseWithoutTeacherThrows() {
        try (StuMgmtDocker docker = new StuMgmtDocker()) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> docker.createCourse("test", "invalid", "Test"));
            assertEquals("Course must have at least one lecturer", e.getMessage());
        }
    }
    
    @Test
    public void getSvnUrlThrowsIfNotRunning() {
        try (StuMgmtDocker docker = new StuMgmtDocker()) {
            assertFalse(docker.isSvnRunning());
            IllegalStateException e = assertThrows(IllegalStateException.class, () -> docker.getSvnUrl());
            assertEquals("SVN server not started", e.getMessage());
        }
    }
    
    @Test
    public void svnReachable() {
        try (StuMgmtDocker docker = new StuMgmtDocker()) {
            docker.createUser("teacher", "123456");
            String courseId = docker.createCourse("test", "wise2021", "Test", "teacher");
            docker.startSvn(courseId, "teacher");
            // create an assignment so that the rights-management creates an initial access file
            docker.createAssignment(courseId, "Testassignment", AssignmentState.SUBMISSION, Collaboration.SINGLE);
            
            assertAll(
                () -> assertTrue(docker.isSvnRunning()),
                () -> assertHttpServerReachableWithAuth(docker.getSvnUrl(), "teacher", "123456"),
                () -> assertThrows(IllegalStateException.class, () -> docker.startSvn(courseId, "teacher"))
            );
        }
    }
    
    private static void assertAuthSystemAlive(String url) {
        net.ssehub.studentmgmt.sparkyservice_api.ApiClient client = new net.ssehub.studentmgmt.sparkyservice_api.ApiClient();
        client.setBasePath(url);
        
        RoutingControllerApi api = new RoutingControllerApi(client);
        assertDoesNotThrow(api::isAlive);
    }
    
    private static void assertStuMgmtAlive(String url) {
        net.ssehub.studentmgmt.backend_api.ApiClient client = new net.ssehub.studentmgmt.backend_api.ApiClient();
        client.setBasePath(url);
        
        DefaultApi api = new DefaultApi(client);
        assertDoesNotThrow(api::appControllerGetUptime);
    }
    
    private static void assertHttpServerReachable(String url) {
        assertTrue(assertDoesNotThrow(() -> HttpUtils.get(url)).isSuccess());
    }
    
    private static void assertHttpServerReachableWithAuth(String url, String username, String password) {
        assertTrue(assertDoesNotThrow(() -> HttpUtils.getAuthenticated(url, username, password)).isSuccess());
    }
    
}
