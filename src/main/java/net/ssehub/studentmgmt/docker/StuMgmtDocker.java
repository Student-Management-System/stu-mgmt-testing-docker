package net.ssehub.studentmgmt.docker;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import net.ssehub.studentmgmt.backend_api.api.AuthenticationApi;
import net.ssehub.studentmgmt.backend_api.api.CourseApi;
import net.ssehub.studentmgmt.backend_api.api.CourseParticipantsApi;
import net.ssehub.studentmgmt.backend_api.api.GroupApi;
import net.ssehub.studentmgmt.backend_api.model.CourseConfigDto;
import net.ssehub.studentmgmt.backend_api.model.CourseCreateDto;
import net.ssehub.studentmgmt.backend_api.model.CourseDto;
import net.ssehub.studentmgmt.backend_api.model.GroupDto;
import net.ssehub.studentmgmt.backend_api.model.GroupSettingsDto;
import net.ssehub.studentmgmt.backend_api.model.PasswordDto;
import net.ssehub.studentmgmt.sparkyservice_api.ApiClient;
import net.ssehub.studentmgmt.sparkyservice_api.ApiException;
import net.ssehub.studentmgmt.sparkyservice_api.api.AuthControllerApi;
import net.ssehub.studentmgmt.sparkyservice_api.api.RoutingControllerApi;
import net.ssehub.studentmgmt.sparkyservice_api.api.UserControllerApi;
import net.ssehub.studentmgmt.sparkyservice_api.model.AuthenticationInfoDto;
import net.ssehub.studentmgmt.sparkyservice_api.model.ChangePasswordDto;
import net.ssehub.studentmgmt.sparkyservice_api.model.CredentialsDto;
import net.ssehub.studentmgmt.sparkyservice_api.model.UserDto;
import net.ssehub.studentmgmt.sparkyservice_api.model.UsernameDto;

/**
 * A utility class for integration tests that runs a fresh instance of the Student Management System in a Docker
 * container. Multiple instances can safely be used in parallel.
 * <p>
 * The purpose of this class is to ease testing; generally there are not many checks that the input data is valid. If
 * something fails, a {@link DockerException} is thrown. This generally only indicates that setting up a test case
 * failed; it does not allow for proper exception handling.
 * <p>
 * A number of public methods allow to create test data in the student management system. Additionally, getters allow
 * to get the API URLs of the different systems; these can be passed to the application that should be tested.
 * <p>
 * This class requires the content of
 * <a href="https://github.com/Student-Management-System/StuMgmtDocker">StuMgmtDocker</a>. It contains the Dockerfiles
 * and <code>docker-compose.yml</code> that are used to start the docker containers. The path to the root directory of
 * this repository (the one containing <code>docker-compose.yml</code>) needs to be passed to this class in either of
 * the following ways (higher entries take precedence over lower entries):
 * <ul>
 *  <li>As an argument to the constructor ({@link #StuMgmtDocker(File)})</li>
 *  <li>As the system property {@value #DOCKER_PROPERTY}</li>
 *  <li>In a file called {@value #DOCKER_LOCATION_FILE}; the first line of this file is used as the path</li>
 * </ul>
 * 
 * @author Adam
 */
public class StuMgmtDocker implements AutoCloseable {

    private static final String DOCKER_PROPERTY = "net.ssehub.studentmgmt.docker.rootPath";
    
    private static final String DOCKER_LOCATION_FILE = "stu-mgmt-docker-rootPath.txt";
    
    private File dockerDirectory;
    
    private String dockerId;
    
    private int authPort;
    
    private int mgmtPort;
    
    private int webPort;
    
    private boolean withSvn;
    
    private int svnPort;
    
    private Map<String, String> userPasswords;
    
    private Map<String, String> userMgmtIds;
    
    private Map<String, String> teachersOfCourse;
    
    /**
     * Starts a new instance of the Student Management System in docker containers. Waits until the services are fully
     * started.
     * 
     * @param dockerDirectory The directory where the <code>docker-compose.yml</code> file for the student management
     *      system lies.
     * @param withSvn Whether a SVN server should be set up, too.
     * 
     * @throws IllegalArgumentException If the given directory is not a directory or does not contain a
     *      docker-compose.yml file.
     * @throws DockerException If executing docker fails.
     */
    public StuMgmtDocker(File dockerDirectory, boolean withSvn) throws DockerException {
        if (!dockerDirectory.isDirectory()) {
            throw new IllegalArgumentException(dockerDirectory + " is not a directory");
        }
        if (!new File(dockerDirectory, "docker-compose.yml").isFile()) {
            throw new IllegalArgumentException(dockerDirectory + " does not contain a docker-compose.yml file");
        }
        this.dockerDirectory = dockerDirectory;
        this.withSvn = withSvn;
        
        this.dockerId = String.format("stu-mgmt-testing-%04d", (int) (Math.random() * 1024));
        this.authPort = generateRandomPort();
        this.mgmtPort = generateRandomPort();
        this.webPort = generateRandomPort();
        this.svnPort = generateRandomPort();

        startDocker();
        
        this.userPasswords = new HashMap<>();
        this.userPasswords.put("admin_user", "admin_pw");
        
        this.userMgmtIds = new HashMap<>();
        this.teachersOfCourse = new HashMap<>();
        
        System.out.println("Waiting for services to be up...");
        waitUntilAuthReachable();
    }
    
    /**
     * Starts a new instance of the Student Management System in docker containers. Waits until the services are fully
     * started.
     * 
     * @throws DockerException If executing docker fails.
     */
    public StuMgmtDocker() {
        this(getDockerRootPath(), false);
    }
    
    /**
     * Starts a new instance of the Student Management System in docker containers. Waits until the services are fully
     * started.
     * 
     * @param withSvn Whether a SVN server should be set up, too.
     * 
     * @throws DockerException If executing docker fails.
     */
    public StuMgmtDocker(boolean withSvn) {
        this(getDockerRootPath(), withSvn);
    }

    /**
     * Gets the path to the <code>docker-compose.yml</code> file from either the system property or the configuration
     * file.
     * 
     * @return The path to the docker root directory.
     * 
     * @throws DockerException If finding the directory fails.
     */
    private static File getDockerRootPath() throws DockerException {
        String configuredPath = System.getProperty(DOCKER_PROPERTY);
        if (configuredPath == null) {
            File configFile = new File(DOCKER_LOCATION_FILE);
            if (configFile.isFile()) {
                try (BufferedReader in = new BufferedReader(new FileReader(configFile))) {
                    configuredPath = in.readLine();
                } catch (IOException e) {
                    throw new DockerException("Failed to read " + DOCKER_LOCATION_FILE, e);
                }
            }
        }
        
        if (configuredPath == null) {
            throw new DockerException("Path to docker-compose.yml not configured; either set the " + DOCKER_PROPERTY
                    + " property or provide a file " + DOCKER_LOCATION_FILE + " in the current working directory");
        }
        
        return new File(configuredPath);
    }
    
    /**
     * Stops and removes the docker containers.
     * 
     * @throws DockerException If stopping the containers fails.
     */
    @Override
    public void close() throws DockerException {
        stopDocker();
    }
    
    /**
     * Generates a random ephemeral port number.
     *  
     * @return A number between 49152 and 65535.
     */
    private int generateRandomPort() {
        return  (int) (Math.random() * (65535 - 49152)) + 49152;
    }
    
    /**
     * Helper method to start the docker containers.
     * 
     * @throws DockerException If starting the containers fails.
     */
    private void startDocker() throws DockerException {
        runProcess("docker-compose", "--project-name", dockerId, "up", "--detach");
    }
    
    /**
     * Helper method to stop and remove the docker containers.
     * 
     * @throws DockerException If stopping the containers fails.
     */
    private void stopDocker() throws DockerException {
        runProcess("docker-compose", "--project-name", dockerId, "down");
    }
    
    /**
     * Runs a process in {@link #dockerDirectory} with the proper environment variables set.
     * 
     * @param command The command to run.
     * 
     * @throws DockerException If running the command fails.
     */
    private void runProcess(String... command) throws DockerException {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(dockerDirectory);
        pb.inheritIO();
        
        Properties envArgs = new Properties();
        try (InputStream in = getClass().getResourceAsStream("/net/ssehub/studentmgmt/docker/args.properties")) {
            envArgs.load(in);
        } catch (IOException e) {
            throw new DockerException("Can't load properties file with environment arguments", e);
        }
        
        Map<String, String> environment = pb.environment();
        for (Entry<Object, Object> entry : envArgs.entrySet()) {
            environment.put(entry.getKey().toString(), entry.getValue().toString());
        }
        
        environment.put("FRONTEND_API_BASE_URL", getAuthUrl());
        environment.put("SPARKY_PORT", Integer.toString(authPort));
        environment.put("BACKEND_PORT", Integer.toString(mgmtPort));
        environment.put("FRONTEND_PORT", Integer.toString(webPort));
        environment.put("SVN_PORT", Integer.toString(svnPort));
        
        if (withSvn) {
            environment.put("COMPOSE_PROFILES", "svn");
        }
        
        Process p;
        try {
            p = pb.start();
        } catch (IOException e) {
            throw new DockerException("Failed to execute docker compose", e);
        }
        
        boolean interrupted;
        do {
            try {
                p.waitFor();
                interrupted = false;
            } catch (InterruptedException e) {
                interrupted = true;
            }
        } while (interrupted);
    }
    
    /**
     * Helper method that waits until the auth system (sparky-service) is alive (i.e. responds to heartbeat API).
     */
    private void waitUntilAuthReachable() {
        ApiClient client = new ApiClient();
        client.setBasePath(getAuthUrl());
        RoutingControllerApi api = new RoutingControllerApi(client);
        
        long tStart = System.currentTimeMillis();
        boolean success;
        do {
            try {
                api.isAlive();
                success = true;
            } catch (ApiException e) {
                success = false;
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e1) {
                }
            }
        } while (!success && System.currentTimeMillis() - tStart < 20000 /* 20 seconds */);
    }
    
    /**
     * Returns the URL for the Sparky-Service system.
     * 
     * @return The URL of the auth system
     */
    public String getAuthUrl() {
        return "http://localhost:" + authPort;
    }
    
    /**
     * Returns the URL of the Student Management System.
     * 
     * @return The stu-mgmt URL.
     */
    public String getStuMgmtUrl() {
        return "http://localhost:" + mgmtPort;
    }
    
    /**
     * Returns the ULR of the web client.
     * 
     * @return The web client URL.
     */
    public String getWebUrl() {
        return "http://localhost:" + webPort + "/";
    }
    
    /**
     * Returns the URL of the SVN server.
     * 
     * @return The URL of the SVN server.
     * 
     * @throws IllegalStateException If there is no SVN server set up.
     * 
     * @see #StuMgmtDocker(boolean)
     * @see #isWithSvn()
     */
    public String getSvnUrl() throws IllegalStateException {
        if (!withSvn) {
            throw new IllegalStateException("SVN server not enabled");
        }
        
        return "http://localhost:" + svnPort + "/svn/submission/";
    }
    
    
    /**
     * Whether an SVN server is running.
     * 
     * @return If an SVN is running.
     */
    public boolean isWithSvn() {
        return withSvn;
    }
    
    /**
     * Creates a user in the student management system.
     * 
     * @param name The username of the new user.
     * @param password The password of the new user.
     * 
     * @throws DockerException If creating the user fails.
     */
    public void createUser(String name, String password) throws DockerException {
        if (password.length() < 6) {
            throw new IllegalArgumentException("Password must be at least 6 characters");
        }
        
        userPasswords.put(name, password);
        
        ApiClient client = getAuthenticatedAuthClient("admin_user");
        
        UserControllerApi api = new UserControllerApi(client);
        
        UserDto user;
        try {
            UsernameDto username = new UsernameDto();
            username.setUsername(name);
            
            user = api.createLocalUser(username);
        } catch (ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        try {
            ChangePasswordDto pwDto = new ChangePasswordDto();
            pwDto.setNewPassword(password);
            user.setPasswordDto(pwDto);
            
            api.editUser(user);
        } catch (ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        // make user "known" to stu-mgmt by calling its auth route
        net.ssehub.studentmgmt.backend_api.ApiClient backendClient = getAuthenticatedBackendClient(name);
        AuthenticationApi backendApi = new AuthenticationApi(backendClient);
        try {
            net.ssehub.studentmgmt.backend_api.model.UserDto dto = backendApi.whoAmI();
            userMgmtIds.put(name, dto.getId());
            
        } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        System.out.println("Created user " + name + " with password: " + password);
    }
    
    /**
     * Helper method to get a token for user. Uses the cached password.
     * 
     * @param user The user to get the token for.
     * 
     * @return A valid token for the user.
     * 
     * @throws DockerException If getting the token fails.
     */
    private String getToken(String user) throws DockerException {
        ApiClient client = new ApiClient();
        client.setBasePath(getAuthUrl());
        
        CredentialsDto credentials = new CredentialsDto();
        credentials.setUsername(user);
        credentials.setPassword(userPasswords.get(user));
        
        AuthControllerApi api = new AuthControllerApi(client);
        AuthenticationInfoDto auth;
        try {
            auth = api.authenticate(credentials);
        } catch (ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        return auth.getToken().getToken();
    }
    
    /**
     * Helper method to get an authenticated client for the auth system (sparky-service) for a given user.
     * 
     * @param username The user to get the client for.
     * 
     * @return The authenticated client.
     * 
     * @throws DockerException If authenticating the client fails.
     */
    private ApiClient getAuthenticatedAuthClient(String username) throws DockerException {
        ApiClient client = new ApiClient();
        client.setBasePath(getAuthUrl());
        client.setAccessToken(getToken(username));
        return client;
    }
    
    /**
     * Helper method to get an authenticated client for the stu-mgmt backend system for a given user.
     * 
     * @param username The user to get the client for.
     * 
     * @return The authenticated client.
     * 
     * @throws DockerException If authenticating the client fails.
     */
    private net.ssehub.studentmgmt.backend_api.ApiClient getAuthenticatedBackendClient(String username)
            throws DockerException {
        
        net.ssehub.studentmgmt.backend_api.ApiClient client = new net.ssehub.studentmgmt.backend_api.ApiClient();
        client.setBasePath(getStuMgmtUrl());
        client.setAccessToken(getToken(username));
        return client;
    }
    
    /**
     * Creates a course in the student management system.
     * 
     * @param shortName The short name of the course.
     * @param semester The semester of the course, e.g. <code>wise2021</code>.
     * @param title The title of the course (human readable name).
     * @param lecturers The usernames that should be lecturers in this course.
     * 
     * @return The ID of the newly created course.
     * 
     * @throws DockerException If creating the course fails.
     */
    public String createCourse(String shortName, String semester, String title, String... lecturers)
            throws DockerException {
        
        net.ssehub.studentmgmt.backend_api.ApiClient client = getAuthenticatedBackendClient("admin_user");
        
        CourseApi courseApi = new CourseApi(client);
        
        GroupSettingsDto groupSettings = new GroupSettingsDto();
        groupSettings.setAllowGroups(true);
        groupSettings.setSelfmanaged(true);
        groupSettings.setAutoJoinGroupOnCourseJoined(false);
        groupSettings.setMergeGroupsOnAssignmentStarted(false);
        groupSettings.setSizeMin(BigDecimal.ZERO);
        groupSettings.setSizeMax(BigDecimal.TEN);
        
        CourseConfigDto courseConfig = new CourseConfigDto();
        courseConfig.setGroupSettings(groupSettings);
        
        CourseCreateDto courseCreate = new CourseCreateDto();
        courseCreate.setShortname(shortName);
        courseCreate.setSemester(semester);
        courseCreate.setTitle(title);
        courseCreate.setLecturers(Arrays.asList(lecturers));
        courseCreate.setIsClosed(false);
        courseCreate.setConfig(courseConfig);
        
        String courseId;
        
        try {
            CourseDto dto = courseApi.createCourse(courseCreate);
            
            courseId = dto.getId();
            
        } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        this.teachersOfCourse.put(courseId, lecturers[0]);
        
        System.out.println("Created course " + courseId + " (" + title + ")");
        return courseId;
    }
    
    /**
     * Enrolls a given user as a student in the given course.
     * 
     * @param courseId The ID of the course to enroll into.
     * @param student The username of the student to enrol.
     * 
     * @throws DockerException If enrolling the student fails.
     */
    public void enrollStudentInCourse(String courseId, String student) throws DockerException {
        net.ssehub.studentmgmt.backend_api.ApiClient client = getAuthenticatedBackendClient(student);
        CourseParticipantsApi api = new CourseParticipantsApi(client);
        
        try {
            PasswordDto pw = new PasswordDto();
            pw.setPassword("");
            
            api.addUser(pw, courseId, userMgmtIds.get(student));
        } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        System.out.println("Enrolled " + student + " in course " + courseId);
    }
    
    /**
     * Creates a group of students in a given course.
     * 
     * @param courseId The ID of the course to create the group in.
     * @param groupName The name of the group.
     * @param members The usernames of the students to add to the group.
     * 
     * @return The ID of the created group.
     * 
     * @throws DockerException If creating the group fails.
     */
    public String createGroupInCourse(String courseId, String groupName, String... members) throws DockerException {
        net.ssehub.studentmgmt.backend_api.ApiClient client
                = getAuthenticatedBackendClient(teachersOfCourse.get(courseId));
        GroupApi api = new GroupApi(client);
        
        GroupDto group = new GroupDto();
        group.setName(groupName);
        
        try {
            group = api.createGroup(group, courseId);
        } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        PasswordDto pw = new PasswordDto();
        pw.setPassword("");
        
        for (String member : members) {
            try {
                api.addUserToGroup(pw, courseId, group.getId(), userMgmtIds.get(member));
            } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
                System.err.println(e.getResponseBody());
                throw new DockerException(e);
            }
        }
        
        System.out.println("Created group " + groupName + " with members: " + Arrays.toString(members));
        
        return group.getId();
    }
    
    /**
     * Runs an instance until enter is pressed in the console.
     * 
     * @param args Command line arguments; ignored.
     * 
     * @throws IOException If reading System.in fails.
     */
    public static void main(String[] args) throws IOException {
        try (StuMgmtDocker docker = new StuMgmtDocker(true)) {
            
            docker.createUser("adam", "123456");
            docker.createUser("student1", "123456");
            docker.createUser("student2", "123456");
            docker.createUser("student3", "123456");
            docker.createUser("student4", "123456");
            
            String courseId = docker.createCourse("java", "wise2021", "Programmierpraktikum: Java", "adam");
            docker.enrollStudentInCourse(courseId, "student1");
            docker.enrollStudentInCourse(courseId, "student2");
            docker.enrollStudentInCourse(courseId, "student3");
            docker.enrollStudentInCourse(courseId, "student4");
            
            docker.createGroupInCourse(courseId, "JP001", "student1", "student3");
            docker.createGroupInCourse(courseId, "JP002", "student2", "student4");
            
            System.out.println();
            System.out.println();
            System.out.println("Docker running:");
            System.out.println("Auth: " + docker.getAuthUrl());
            System.out.println("Mgmt: " + docker.getStuMgmtUrl());
            System.out.println("Web:  " + docker.getWebUrl());
            if (docker.isWithSvn()) {
                System.out.println("SVN:  " + docker.getSvnUrl());
            }
            
            System.out.println();
            System.out.println("Press enter to stop");
            
            System.in.read();
            
        } catch (DockerException e) {
            e.printStackTrace();
        }
    }
    
}
