package net.ssehub.studentmgmt.docker;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.lang.ProcessBuilder.Redirect;
import java.math.BigDecimal;
import java.net.ServerSocket;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import net.ssehub.studentmgmt.backend_api.api.AssignmentApi;
import net.ssehub.studentmgmt.backend_api.api.AuthenticationApi;
import net.ssehub.studentmgmt.backend_api.api.CourseApi;
import net.ssehub.studentmgmt.backend_api.api.CourseParticipantsApi;
import net.ssehub.studentmgmt.backend_api.api.DefaultApi;
import net.ssehub.studentmgmt.backend_api.api.GroupApi;
import net.ssehub.studentmgmt.backend_api.api.NotificationApi;
import net.ssehub.studentmgmt.backend_api.model.AssignmentDto;
import net.ssehub.studentmgmt.backend_api.model.AssignmentDto.CollaborationEnum;
import net.ssehub.studentmgmt.backend_api.model.AssignmentDto.StateEnum;
import net.ssehub.studentmgmt.backend_api.model.AssignmentDto.TypeEnum;
import net.ssehub.studentmgmt.backend_api.model.AssignmentUpdateDto;
import net.ssehub.studentmgmt.backend_api.model.CourseConfigDto;
import net.ssehub.studentmgmt.backend_api.model.CourseCreateDto;
import net.ssehub.studentmgmt.backend_api.model.CourseDto;
import net.ssehub.studentmgmt.backend_api.model.GroupDto;
import net.ssehub.studentmgmt.backend_api.model.GroupSettingsDto;
import net.ssehub.studentmgmt.backend_api.model.PasswordDto;
import net.ssehub.studentmgmt.backend_api.model.SubscriberDto;
import net.ssehub.studentmgmt.docker.HttpUtils.HttpResponse;
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
 * @author Lukas
 */
public class StuMgmtDocker implements AutoCloseable {

    private static final String DOCKER_PROPERTY = "net.ssehub.studentmgmt.docker.rootPath";
    
    private static final String DOCKER_LOCATION_FILE = "stu-mgmt-docker-rootPath.txt";
    
    private static final int WAITING_TIMEOUT_MS = 60000;
    
    private File dockerDirectory;
    
    private String dockerId;
    
    private int authPort;
    
    private int mgmtPort;
    
    private int webPort;
    
    private boolean svnRunning;
    
    private int svnPort;
    
    private String svnCourseId;
    
    private Map<String, String> userPasswords;
    
    private Map<String, String> userTokens;
    
    private Map<String, String> userMgmtIds;
    
    private Map<String, String> teachersOfCourse;
    
    /**
     * Starts a new instance of the Student Management System in docker containers. Waits until the services are fully
     * started.
     * 
     * @param dockerDirectory The directory where the <code>docker-compose.yml</code> file for the student management
     *      system lies.
     * 
     * @throws IllegalArgumentException If the given directory is not a directory or does not contain a
     *      docker-compose.yml file.
     * @throws DockerException If executing docker fails.
     */
    public StuMgmtDocker(File dockerDirectory) throws DockerException {
        if (!dockerDirectory.isDirectory()) {
            throw new IllegalArgumentException(dockerDirectory + " is not a directory");
        }
        if (!new File(dockerDirectory, "docker-compose.yml").isFile()) {
            throw new IllegalArgumentException(dockerDirectory + " does not contain a docker-compose.yml file");
        }
        this.dockerDirectory = dockerDirectory;
        
        this.dockerId = String.format("stu-mgmt-testing-%04d", (int) (Math.random() * 10000));
        this.authPort = generateRandomPort();
        this.mgmtPort = generateRandomPort();
        this.webPort = generateRandomPort();
        this.svnPort = generateRandomPort();

        startDocker();
        
        this.userPasswords = new HashMap<>();
        this.userPasswords.put("admin_user", "admin_pw");
        this.userTokens = new HashMap<>();
        
        this.userMgmtIds = new HashMap<>();
        this.teachersOfCourse = new HashMap<>();
        
        System.out.println("Waiting for services to be up...");
        waitUntilAuthReachable();
        waitUntilMgmtBackendReachable();
    }
    
    /**
     * Starts a new instance of the Student Management System in docker containers. Waits until the services are fully
     * started.
     * 
     * @throws DockerException If executing docker fails.
     */
    public StuMgmtDocker() {
        this(getDockerRootPath());
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
     * @return A random open port.
     */
    private int generateRandomPort() {
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            socket.setReuseAddress(true);
            port = socket.getLocalPort();
            
        } catch (IOException e) {
            System.err.println("Failed to get free port: " + e.getMessage());
            System.err.println("Using random port number (might not be free)");
            port = (int) (Math.random() * (65535 - 49152)) + 49152;
        }
        
        return port;
    }
    
    /**
     * Helper method to start the docker containers.
     * 
     * @throws DockerException If starting the containers fails.
     */
    private void startDocker() throws DockerException {
        runProcess(null, "docker-compose", "--project-name", dockerId, "up", "--detach");
    }
    
    /**
     * Helper method to stop and remove the docker containers.
     * 
     * @throws DockerException If stopping the containers fails.
     */
    private void stopDocker() throws DockerException {
        runProcess(null, "docker-compose", "--project-name", dockerId, "down");
    }
    
    /**
     * Starts an SVN server for submissions for the given course.
     * 
     * @param courseId The ID of the course to set the submission SVN up for.
     * @param user The user that the SVN rights-management uses to log into the management system. Should be a teacher
     *      in the course.
     * 
     * @throws DockerException If creating the SVN server or registering it as a listener for the course fails.
     * @throws IllegalStateException If SVN is already running.
     */
    public void startSvn(String courseId, String user) throws DockerException, IllegalStateException {
        if (svnRunning) {
            throw new IllegalStateException("SVN is already running");
        }
        svnRunning = true;
        svnCourseId = courseId;
        
        Map<String, String> env = new HashMap<>();
        env.put("SVN_COURSE", courseId);
        env.put("SVN_MGMT_USER", user);
        env.put("SVN_MGMT_PW", userPasswords.get(user));
        
        runProcess(env, "docker-compose", "--project-name", dockerId, "up", "--detach", "svn");
        
        
        net.ssehub.studentmgmt.backend_api.ApiClient client = getAuthenticatedBackendClient("admin_user");
        NotificationApi api = new NotificationApi(client);
        
        SubscriberDto subscriber = new SubscriberDto();
        subscriber.setName("svn-rights-management");
        subscriber.setUrl("http://svn:4000/rest/update");
        subscriber.setEvents(Collections.singletonMap("ALL", true));
        
        try {
            api.subscribe(subscriber, courseId, subscriber.getName());
        } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        System.out.println("Sarted SVN submission server for course " + courseId);
        System.out.println("Waiting for SVN rights-management to be up...");
        waitUntilSvnRightsManagementReachable();
    }
    
    /**
     * Runs a process in {@link #dockerDirectory} with the proper environment variables set.
     * 
     * @param extraEnv Extra environment variables to set. <code>null</code> if not required.
     * @param command The command to run.
     * 
     * @throws DockerException If running the command fails.
     */
    private void runProcess(Map<String, String> extraEnv, String... command) throws DockerException {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(dockerDirectory);
        pb.inheritIO();
        pb.redirectErrorStream(true);
        
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
        
        if (extraEnv != null) {
            for (Entry<String, String> entry : extraEnv.entrySet()) {
                environment.put(entry.getKey(), entry.getValue());
            }
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
        } while (!success && System.currentTimeMillis() - tStart < WAITING_TIMEOUT_MS);
        
        if (!success) {
            System.out.println("sparky-service not reachable for " + WAITING_TIMEOUT_MS + " ms");
        } else {
            System.out.println("sparky-service reachable (" + (System.currentTimeMillis() - tStart) + " ms)");
        }
    }
    
    /**
     * Helper method that waits until the mgmt backend is alive (i.e. responds to uptime API).
     */
    private void waitUntilMgmtBackendReachable() {
        net.ssehub.studentmgmt.backend_api.ApiClient client = new net.ssehub.studentmgmt.backend_api.ApiClient();
        client.setBasePath(getStuMgmtUrl());
        
        DefaultApi api = new DefaultApi(client);
        
        long tStart = System.currentTimeMillis();
        boolean success;
        do {
            try {
                api.appControllerGetUptime();
                success = true;
            } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
                success = false;
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e1) {
                }
            }
        } while (!success && System.currentTimeMillis() - tStart < WAITING_TIMEOUT_MS);
        
        if (!success) {
            System.out.println("stu-mgmt-backend not reachable for " + WAITING_TIMEOUT_MS + " ms");
        } else {
            System.out.println("stu-mgmt-backend reachable (" + (System.currentTimeMillis() - tStart) + " ms)");
        }
    }
    
    /**
     * Helper method that waits until the rights-management in the SVN server is alive.
     */
    private void waitUntilSvnRightsManagementReachable() {
        // we seem to have no way to contact the rights-management service inside the svn container...
        // thus we hackily just get the log output and grep for the status
        // the line "Rights-Management is up and reachable" is written by the startup script, once the rest server
        //  responds to the heartbeat route
        
        ProcessBuilder pb = new ProcessBuilder("docker-compose", "--project-name", dockerId, "logs", "svn");
        pb.directory(dockerDirectory);
        pb.redirectOutput(Redirect.PIPE);
        pb.redirectError(Redirect.INHERIT);
        
        long tStart = System.currentTimeMillis();
        boolean success = false;
        while (!success && System.currentTimeMillis() - tStart < WAITING_TIMEOUT_MS) {
            try {
                Process process = pb.start();
                
                BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = in.readLine()) != null) {
                    if (line.endsWith("Rights-Management is up and reachable")) {
                        success = true;
                    }
                }
                
            } catch (IOException e) {
                System.err.println("Failed to get docker logs: " + e.getMessage());
            }
            
            if (!success) {
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e) {
                }
            }
        }
        
        if (!success) {
            System.out.println("SVN rights-management not reachable for " + WAITING_TIMEOUT_MS + " ms");
        } else {
            // wait a bit longer, this seems to be required
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
            }
            
            System.out.println("SVN rights-management reachable (" + (System.currentTimeMillis() - tStart) + " ms)");
        }
    }
    
    /**
     * Waits until the given assignment folder exists in the SVN repository.
     * 
     * @param assignmentFolder The name of the assignment folder that should exist in the SVN repository.
     */
    private void waitUntilSvnUpdated(String assignmentFolder) {
        System.out.println("Waiting for " + assignmentFolder + " to exist in the SVN repository...");

        String teacher = teachersOfCourse.get(svnCourseId);
        String teacherPw = userPasswords.get(teacher);
        
        long tStart = System.currentTimeMillis();
        boolean success;
        do {
            
            try {
                HttpResponse response = HttpUtils.getAuthenticated(getSvnUrl() + assignmentFolder, teacher, teacherPw);
                success = response.isSuccess();
                
            } catch (IOException e) {
                success = false;
            }
            
            if (!success) {
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e) {
                }
            }
            
        } while (!success && System.currentTimeMillis() - tStart < WAITING_TIMEOUT_MS);
        
        if (!success) {
            System.out.println(assignmentFolder + " not created for " + WAITING_TIMEOUT_MS + " ms");
        } else {
            System.out.println(assignmentFolder + " exists (" + (System.currentTimeMillis() - tStart) + " ms)");
        }
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
     * @throws IllegalStateException If the SVN server was not started.
     * 
     * @see #startSvn(String, String)
     * @see #isSvnRunning()
     */
    public String getSvnUrl() throws IllegalStateException {
        if (!svnRunning) {
            throw new IllegalStateException("SVN server not started");
        }
        
        return "http://localhost:" + svnPort + "/svn/submission/";
    }
    
    
    /**
     * Whether an SVN server is running.
     * 
     * @return If an SVN is running.
     * 
     * @see #startSvn(String, String)
     */
    public boolean isSvnRunning() {
        return svnRunning;
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
    public String getAuthToken(String user) throws DockerException {
        String token = userTokens.get(user);
        
        if (token == null) {
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
            
            token = auth.getToken().getToken();
            userTokens.put(user, token);
        }
        
        return token;
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
        client.setAccessToken(getAuthToken(username));
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
        client.setAccessToken(getAuthToken(username));
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
        
        if (!semester.matches("sose[0-9]{2}|wise[0-9]{4}")) {
            throw new IllegalArgumentException("Semester must match be in the form of sose21 or wise2122");
        }
        
        if (lecturers.length == 0) {
            throw new IllegalArgumentException("Course must have at least one lecturer");
        }
        
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
    public void enrollStudent(String courseId, String student) throws DockerException {
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
    public String createGroup(String courseId, String groupName, String... members) throws DockerException {
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
     * The state of an assignment.
     */
    public enum AssignmentState {
        INVISIBLE(StateEnum.INVISIBLE,
                net.ssehub.studentmgmt.backend_api.model.AssignmentUpdateDto.StateEnum.INVISIBLE),
        CLOSED(StateEnum.CLOSED,
                net.ssehub.studentmgmt.backend_api.model.AssignmentUpdateDto.StateEnum.CLOSED),
        SUBMISSION(StateEnum.IN_PROGRESS,
                net.ssehub.studentmgmt.backend_api.model.AssignmentUpdateDto.StateEnum.IN_PROGRESS),
        IN_REVIEW(StateEnum.IN_REVIEW,
                net.ssehub.studentmgmt.backend_api.model.AssignmentUpdateDto.StateEnum.IN_REVIEW),
        REVIEWED(StateEnum.EVALUATED,
                net.ssehub.studentmgmt.backend_api.model.AssignmentUpdateDto.StateEnum.EVALUATED);
        
        private StateEnum createValue;
        
        private net.ssehub.studentmgmt.backend_api.model.AssignmentUpdateDto.StateEnum updateValue;

        /**
         * Creates an instance.
         * 
         * @param createValue The corresponding value for the backend-api library when creating an assignment.
         * @param updateValue The corresponding value for the backend-api library when updating an assignment.
         */
        private AssignmentState(StateEnum createValue,
                net.ssehub.studentmgmt.backend_api.model.AssignmentUpdateDto.StateEnum updateValue) {
            this.createValue = createValue;
            this.updateValue = updateValue;
        }
        
    }
    
    /**
     * The collboration type of an assignment.
     */
    public enum Collaboration {
        SINGLE(CollaborationEnum.SINGLE), GROUP(CollaborationEnum.GROUP);
        
        private CollaborationEnum apiValue;
        
        /**
         * Creates an instance.
         * 
         * @param apiValue The corresponding value for the backend-api library.
         */
        private Collaboration(CollaborationEnum apiValue) {
            this.apiValue = apiValue;
        }
        
    }
    
    /**
     * Creates an assignment in the given course.
     * <p>
     * Note that groups are only registered for an assignment in the {@link AssignmentState#SUBMISSION} state; if you
     * want to have groups registered in any other state, create it with state {@link AssignmentState#SUBMISSION} and
     * change to the desired state afterwards (see {@link #changeAssignmentState(String, String, AssignmentState)}).
     * <p>
     * If an SVN server is running for the given course, this method waits until the assignment is created in the SVN
     * repository.
     * 
     * @param courseId The course to create the assignment in.
     * @param name The name of the assignment.
     * @param state The state of the assignment.
     * @param collaboration The collaboration type of the assignment.
     * 
     * @return The ID of the assignment; used e.g. in {@link #changeAssignmentState(String, String, AssignmentState)}.
     * 
     * @throws DockerException If creating the assignment fails.
     */
    public String createAssignment(String courseId, String name, AssignmentState state,
            Collaboration collaboration) throws DockerException {
        
        net.ssehub.studentmgmt.backend_api.ApiClient client
                = getAuthenticatedBackendClient(teachersOfCourse.get(courseId));
        
        AssignmentApi assignmentApi = new AssignmentApi(client);
        
        AssignmentDto assignment = new AssignmentDto();
        assignment.setName(name);
        assignment.setState(state.createValue);
        assignment.setCollaboration(collaboration.apiValue);
        assignment.setType(TypeEnum.HOMEWORK);
        assignment.setPoints(BigDecimal.TEN);
        
        try {
            assignment = assignmentApi.createAssignment(assignment, courseId);
        } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        System.out.println("Created " + collaboration.name() +  "-assignment " + name + " with status " + state.name());
        
        if (svnRunning && courseId.equals(svnCourseId)) {
            waitUntilSvnUpdated(assignment.getName());
        }
        
        return assignment.getId();
    }
    
    /**
     * Changes the state of an assignment.
     * <p>
     * If an SVN server is running for the given course, this method waits until the assignment is created in the SVN
     * repository.
     * 
     * @param courseId The course where the assignment is in.
     * @param assignmentId The ID of the assignment, as returned by
     *      {@link #createAssignment(String, String, AssignmentState, Collaboration)}.
     * @param state The new state of the assignment.
     * 
     * @throws DockerException If changing the state fails.
     */
    public void changeAssignmentState(String courseId, String assignmentId, AssignmentState state)
            throws DockerException {
        
        net.ssehub.studentmgmt.backend_api.ApiClient client
                = getAuthenticatedBackendClient(teachersOfCourse.get(courseId));

        AssignmentApi assignmentApi = new AssignmentApi(client);
        
        AssignmentUpdateDto update = new AssignmentUpdateDto();
        update.setState(state.updateValue);
        
        AssignmentDto assignment;
        try {
            assignment = assignmentApi.updateAssignment(update, courseId, assignmentId);
        } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        System.out.println("Changed assignment " + assignment.getName() + " to status " + state.name());
        
        if (svnRunning && courseId.equals(svnCourseId)) {
            waitUntilSvnUpdated(assignment.getName());
        }
    }
    
    /**
     * Gets the content of the given file on the SVN server over HTTP.
     * 
     * @param filepath The path of the file on the server without a leading slash.
     *      Should include assignment and group name.
     * 
     * @return The content of the file as a string.
     * 
     * @throws DockerException If getting the file fails.
     */
    public String getSvnFileOverHttp(String filepath) throws DockerException {
        String teacher = teachersOfCourse.get(svnCourseId);
        String url = getSvnUrl() + filepath;
        
        HttpResponse response;
        try {
            response = HttpUtils.getAuthenticated(url, teacher, userPasswords.get(teacher));
        } catch (IOException e) {
            throw new DockerException(e);
        }
        
        if (!response.isSuccess()) {
            throw new DockerException("Response not successful: " + response);
        }
        
        if (response.getBody().isEmpty()) {
            throw new DockerException("Response has no body: " + response);
        }
        
        return response.getBody().get();
    }
    
    /**
     * Gets the names of the files inside a given directory on the SVN server over HTTP.
     * 
     * @param directory The path of the directory on the server without a leading slash.
     * 
     * @return The filenames (including sub-directories) in the directory. Sub-directory names will have a trailing
     *      slash after their name.
     * 
     * @throws DockerException If getting the directory content fails.
     */
    public Set<String> getSvnDirectoryContent(String directory) throws DockerException {
        String content = getSvnFileOverHttp(directory);
        // fix a parsing problem
        content = content.replaceAll("<hr noshade>", "<hr />");
        
        Set<String> filenames;
        
        try  {
            DocumentBuilder dBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            Document doc = dBuilder.parse(new InputSource(new StringReader(content)));
            doc.getDocumentElement().normalize();
            
            NodeList contentList = doc.getElementsByTagName("li");
            filenames = new HashSet<>(contentList.getLength());
            
            for (int i = 0; i < contentList.getLength(); i++) {
                String filename = contentList.item(i).getTextContent();
                if (!filename.equals("..")) {
                    filenames.add(filename);
                }
            }
            
        } catch (SAXException | IOException | ParserConfigurationException e) {
            throw new DockerException("Failed to parse HTML", e);
        }
        
        return filenames;
    }
    
    /**
     * Runs an instance until enter is pressed in the console.
     * 
     * @param args Command line arguments; ignored.
     * 
     * @throws IOException If reading System.in fails.
     */
    public static void main(String[] args) throws IOException {
        try (StuMgmtDocker docker = new StuMgmtDocker()) {
            
            docker.createUser("svn", "abcdefgh");
            docker.createUser("adam", "123456");
            docker.createUser("student1", "123456");
            docker.createUser("student2", "123456");
            docker.createUser("student3", "123456");
            docker.createUser("student4", "123456");
            
            String courseId = docker.createCourse("java", "wise2021", "Programmierpraktikum: Java", "adam", "svn");
            
            docker.enrollStudent(courseId, "student1");
            docker.enrollStudent(courseId, "student2");
            docker.enrollStudent(courseId, "student3");
            docker.enrollStudent(courseId, "student4");
            
            docker.createGroup(courseId, "JP001", "student1", "student3");
            docker.createGroup(courseId, "JP002", "student2", "student4");
            
            String a1 = docker.createAssignment(courseId, "Homework01", AssignmentState.INVISIBLE, Collaboration.GROUP);
            String a2 = docker.createAssignment(courseId, "Homework02", AssignmentState.INVISIBLE, Collaboration.GROUP);
            docker.createAssignment(courseId, "Testat01", AssignmentState.INVISIBLE, Collaboration.SINGLE);
            
            docker.changeAssignmentState(courseId, a1, AssignmentState.SUBMISSION);
            docker.changeAssignmentState(courseId, a1, AssignmentState.IN_REVIEW);
            
            // start the SVN late, so that only one assignment change event triggers a full update
            docker.startSvn(courseId, "svn");
            
            docker.changeAssignmentState(courseId, a2, AssignmentState.SUBMISSION);
            
            System.out.println();
            System.out.println();
            System.out.println("Docker running:");
            System.out.println("Auth: " + docker.getAuthUrl());
            System.out.println("Mgmt: " + docker.getStuMgmtUrl());
            System.out.println("Web:  " + docker.getWebUrl());
            if (docker.isSvnRunning()) {
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
